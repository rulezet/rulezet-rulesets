import "pe"
rule UOmCgbXygCe_14335 {
  meta:
    description = "UOmCgbXygCe.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
    date        = "2022-09-12"
    hash1       = "f4c085ef1ba7e78a17a9185e4d5e06163fe0e39b6b0dc3088b4c1ed11c0d726b"

  strings:
    $s1  = "runsuite.log" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "f73.exe" fullword ascii
    $s4  = "Processing test line %ld %s leaked %d" fullword ascii
    $s5  = "Internal error: xmlSchemaTypeFixup, complex type '%s': the <simpleContent><restriction> is missing a <simpleType> child, but was" ascii
    $s6  = "The target namespace of the included/redefined schema '%s' has to be absent or the same as the including/redefining schema's tar" ascii
    $s7  = "The target namespace of the included/redefined schema '%s' has to be absent, since the including/redefining schema has no target" ascii
    $s8  = "A <simpleType> is expected among the children of <restriction>, if <simpleContent> is used and the base type '%s' is a complex t" ascii
    $s9  = "there is at least one entity reference in the node-tree currently being validated. Processing of entities with this XML Schema p" ascii
    $s10 = "## %s test suite for Schemas version %s" fullword ascii
    $s11 = "Internal error: %s, " fullword ascii
    $s12 = "If <simpleContent> and <restriction> is used, the base type must be a simple type or a complex type with mixed content and parti" ascii
    $s13 = "For a string to be a valid default, the type definition must be a simple type or a complex type with simple content or mixed con" ascii
    $s14 = "For a string to be a valid default, the type definition must be a simple type or a complex type with mixed content and a particl" ascii
    $s15 = "Could not open the log file, running in verbose mode" fullword ascii
    $s16 = "not validating will not read content for PE entity %s" fullword ascii
    $s17 = "Skipping import of schema located at '%s' for the namespace '%s', since this namespace was already imported with the schema loca" ascii
    $s18 = "(annotation?, (simpleContent | complexContent | ((group | all | choice | sequence)?, ((attribute | attributeGroup)*, anyAttribut" ascii
    $s19 = "get namespace" fullword ascii
    $s20 = "instance %s fails to parse" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 7000KB and
    (pe.imphash() == "bcf185f1308ffd9e4249849d206d9d0c" and pe.exports("xmlEscapeFormatString") or 12 of them)
}