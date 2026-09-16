rule PoSlurpFile: PoSlurp {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp PoS Malware on Disk PoSlurp executable"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $hex1 = { 81 C2 FF 5C F3 22 52 56 E8 }  
  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $hex1

}