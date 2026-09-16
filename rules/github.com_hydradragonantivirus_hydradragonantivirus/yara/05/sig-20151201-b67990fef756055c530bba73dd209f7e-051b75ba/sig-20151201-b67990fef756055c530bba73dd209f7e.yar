rule sig_20151201_b67990fef756055c530bba73dd209f7e {
  meta:
    description = "datamaliciousorder - file 20151201_b67990fef756055c530bba73dd209f7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac8cff5b6df642a5fbf70de437a5447926be8b213cce384f88145439565f29e6"

  strings:
    $s1 = "var str=\"5553555E0D0A020B24011C1405101001070C4A070B095E215E0F11080D0A05160905034A16115E17565E5550505C5D5D545157515E55\";var o2=" ascii
    $s2 = "'92)+\"';var f5='(var ';function k9(){return m9;};var p6='d;';var e1='xe\",';var r1='bject';var g6='en(';var k6='; xa';var e5='s" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}