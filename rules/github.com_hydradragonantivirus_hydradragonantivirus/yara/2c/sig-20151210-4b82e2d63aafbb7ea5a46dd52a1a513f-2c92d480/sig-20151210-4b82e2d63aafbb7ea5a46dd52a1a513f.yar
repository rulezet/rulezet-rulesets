rule sig_20151210_4b82e2d63aafbb7ea5a46dd52a1a513f {
  meta:
    description = "datamaliciousorder - file 20151210_4b82e2d63aafbb7ea5a46dd52a1a513f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a3fbe32bc42655b8057cdcbe037a7f9ed5e5f6e33888f5e6ad1fe709df822cc"

  strings:
    $s1 = "var str=\"5553565E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E215E0506130100000D0A03171011000D0B4A070B095E17555E55" ascii
    $s2 = "ion q3(){return p1;};var s0='+) { ';var x6='r)';var r9='= WSc';var n2='lose';var h8=' {';var a3='r ';var p3='B.Str';var i2='var " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}