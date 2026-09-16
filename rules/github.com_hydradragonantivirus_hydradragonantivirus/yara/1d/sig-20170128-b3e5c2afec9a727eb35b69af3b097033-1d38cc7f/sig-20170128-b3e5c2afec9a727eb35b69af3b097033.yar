rule sig_20170128_b3e5c2afec9a727eb35b69af3b097033 {
  meta:
    description = "datamaliciousorder - file 20170128_b3e5c2afec9a727eb35b69af3b097033.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49cb2587d876e37675416dc9fa7b68efecef7e58b8c7f0e55b3a585aef968d4f"

  strings:
    $s1  = "var jusicl = new Function(\"ikfoqavazekuv\", \"return WS\" + \"cr\" + ewylzics + \"teObject(ikfoqavazekuv)\");" fullword ascii
    $s2  = "var mzonhyclaz = undefined;" fullword ascii
    $s3  = "return hroxkajnine;" fullword ascii
    $s4  = "var vkamahesbu = null;" fullword ascii
    $s5  = "switch (itoharmonq()) {" fullword ascii
    $s6  = "var zsoxma = false;" fullword ascii
    $s7  = "var iqxuhokaw = null;" fullword ascii
    $s8  = "function qomva() {" fullword ascii
    $s9  = "var lgovrixwuge = true;" fullword ascii
    $s10 = "var wbajyxi = undefined;" fullword ascii
    $s11 = "var arpihtawc = null;" fullword ascii
    $s12 = "var nvymxoz = true;" fullword ascii
    $s13 = "if (amixiw === false) {" fullword ascii
    $s14 = "var odabivhi = null;" fullword ascii
    $s15 = "if (wigmysu == null) {" fullword ascii
    $s16 = "function itoharmonq() {" fullword ascii
    $s17 = "var qagoxubl = false;" fullword ascii
    $s18 = "var zjolhoci = null;" fullword ascii
    $s19 = "if (alwozpebu == undefined) {" fullword ascii
    $s20 = "if (zqomwyhpajba === null) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}