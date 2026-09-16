rule sig_20161128_84e98163e30d14e880771838aac3c630 {
  meta:
    description = "datamaliciousorder - file 20161128_84e98163e30d14e880771838aac3c630.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16cbfd46aafef207e3d5f5ff5bbb671096b40217299f9eed6bf0b3989f824404"

  strings:
    $s1  = "return new Function(ebod + abhanu + \"object')[pege]('C:\\\\\\\\')['type']['length'] > 1\");" fullword ascii
    $s2  = "var abhanu = \"Object('scripting.fileSystem\";" fullword ascii
    $s3  = "var ojgocjunj = null;" fullword ascii
    $s4  = "var efjajja = null;" fullword ascii
    $s5  = "return osihtydxu;" fullword ascii
    $s6  = "function miremijf() {" fullword ascii
    $s7  = "function ajonc() {" fullword ascii
    $s8  = "return \"ihogmun\";" fullword ascii
    $s9  = "var sufy = undefined;" fullword ascii
    $s10 = "var yrgasvil = false;" fullword ascii
    $s11 = "function ockomob() {" fullword ascii
    $s12 = "function benwa() {" fullword ascii
    $s13 = "function ftyce() {" fullword ascii
    $s14 = "var nhadeximh = undefined;" fullword ascii
    $s15 = "switch (hbupigz) {" fullword ascii
    $s16 = "return sufy;" fullword ascii
    $s17 = "return uqbuhi;" fullword ascii
    $s18 = "var rwijnoly = null;" fullword ascii
    $s19 = "var fbewawulne = false;" fullword ascii
    $s20 = "function dhyppavuqy() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}