rule sig_20161102_287a1c1ae576ccd19fae8aa12f040042 {
  meta:
    description = "datamaliciousorder - file 20161102_287a1c1ae576ccd19fae8aa12f040042.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf56876f54e12a4ea6ae83c86745d833fc48d7400f6669b385be0fe45bf16ff9"

  strings:
    $s1  = "return lycdolra;" fullword ascii
    $s2  = "return qyjaqy;" fullword ascii
    $s3  = "switch (trigbusoc) {" fullword ascii
    $s4  = "return ywufujk;" fullword ascii
    $s5  = "return digy;" fullword ascii
    $s6  = "var gipkalna = undefined;" fullword ascii
    $s7  = "return ddilifn;" fullword ascii
    $s8  = "var ylupsi = null;" fullword ascii
    $s9  = "var ojnysqep = typeof document;" fullword ascii
    $s10 = "var fryljihr = typeof undefined;" fullword ascii
    $s11 = "var wefkan = false;" fullword ascii
    $s12 = "switch (dlejypidli()) {" fullword ascii
    $s13 = "function dlejypidli() {" fullword ascii
    $s14 = "var ofarihna = typeof undefined;" fullword ascii
    $s15 = "return ejmanork;" fullword ascii
    $s16 = "return anasudusm;" fullword ascii
    $s17 = "var gylpuwic = undefined;" fullword ascii
    $s18 = "if (owsewdicju === true) {" fullword ascii
    $s19 = "if (rpyxwaqu() == undefined) {" fullword ascii
    $s20 = "var abolansi = undefined;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}