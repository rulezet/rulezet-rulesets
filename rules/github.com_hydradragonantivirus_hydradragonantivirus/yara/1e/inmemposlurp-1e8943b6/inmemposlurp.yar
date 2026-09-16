rule inMemPoSlurp: PoSlurp {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp PoS Malware in Memory PoSlurp"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $hex1 = { C6 45 ED 65 C6 45 EE 72 C6 45 EF 6E C6 45 F0 65 }  
    $hex2 = { E8 EE FD FF FF 68 88 13 00 00 FF D6 8D 44 24 18 50 FF D7 8D 44 24 10 50 8D 44 24 1C 50 FF D3 8B 44 24 10 2B 05 80 50 40 00 8B 4C 24 14 1B 0D 84 50 40 00 6A 00 68 80 96 98 00 51 50 E8 B7 05 00 00 6A 3C 33 D2 59 F7 F1 3B 05 2C 40 40 00 72 B0 }  
  condition:
    all of them

}