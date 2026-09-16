rule sig_20170401_6488b5fc036553fdad166bc1f6ab2b77 {
  meta:
    description = "datamaliciousorder - file 20170401_6488b5fc036553fdad166bc1f6ab2b77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fa91904eb518fddfdb14b9f144c2ec0e551212876cf4c67253301e5313661b3"

  strings:
    $s1 = "var ahat = new Array('/','t',\"GET\",\":\",'p','h','S','a',\"T\",'');" fullword ascii
    $s2 = "while(tersa < 10){tersa++;}" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}