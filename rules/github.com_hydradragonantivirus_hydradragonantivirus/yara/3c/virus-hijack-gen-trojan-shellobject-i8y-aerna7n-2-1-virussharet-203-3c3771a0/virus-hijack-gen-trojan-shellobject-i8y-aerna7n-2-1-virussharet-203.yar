rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_2_1_VirusShareT_203 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_2_1.vir, VirusShareTrojanDownLoader4345326.vir, VirusShareTrojanDownLoader4346565.vir, VirusShareTrojanDownLoader4347106.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "515f91b73a4da057065c29ebbecbae70321dc098e67f2f0e6528f1be3a69f5cd"
    hash2       = "e9a905d9e522c0feed6b811e113bb2fe6e642118902e5a9e2528282bb6fbe179"
    hash3       = "e7d5694ad906b707cd6aef9df07e2651fe947441fc4cfa8a55a6651da6e59b20"
    hash4       = "a1c59b89c79d51496bca3bb67723db963900699f5db3b9e4f09fae181c9a9120"

  strings:
    $s1  = "Error Processing Header %s<SOAP Response Packet: result element expected, received \"%s\"" fullword wide
    $s2  = "Invalid duration string: %s,Millisecond Values must be between 000 - 999-Year portion of date too large for conversion#Hour Offs" wide
    $s3  = "No URL was specified for 'GET';Invalid url '%s' - only supports 'http' and 'https' schemes.No class registered for invokable int" wide
    $s4  = "PortName^<html><head></head><body><h1>Error Encountered</h1><P>Interface %s not found</P></body></html>V<html><head></head><body" wide
    $s5  = "No WSDL or URL property was set in the THTTPRIO component. You must set the WSDL or URL property before invoking the Web Service" wide
    $s6  = "EK Agent (Interface version SRV 2.01)" fullword wide
    $s7  = "Unknown SOAPAction %sMClasses that represent scalar types must decsend from TRemotable, %s does notJMust allow multiref output f" wide
    $s8  = "Array type expected. Node %s=Multidimensional variant arrays not supported in this release" fullword wide
    $s9  = "!\"should never get here\"" fullword ascii
    $s10 = "Invalid SOAP request$Multiple body elements not supported\"Unsupported calling convention: %sSRemote Method Call: unsupported ca" wide
    $s11 = "ContentModel not set@Facets and Enumeration not allowed on this kind of datatype \"%s\"Invalid built-in type name \"%s\"" fullword wide
    $s12 = "+Mismatched paramaters to RegisterChildNodes+Element does not contain a single text node4DOM Implementation does not support IDO" wide
    $s13 = "WebService Listing WebService Listing Administrator" fullword wide
    $s14 = "Service Info Page" fullword wide
    $s15 = "Unsuppported variant type" fullword wide
    $s16 = "varDate type not supported" fullword wide
    $s17 = "varVariant type not supported" fullword wide
    $s18 = "!Unsupported SOAP encodingStyle %s" fullword wide
    $s19 = "Software Security System" fullword wide
    $s20 = "Node cannot be null Microsoft MSXML is not installed)\"%s\" DOMImplementation already registered" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}