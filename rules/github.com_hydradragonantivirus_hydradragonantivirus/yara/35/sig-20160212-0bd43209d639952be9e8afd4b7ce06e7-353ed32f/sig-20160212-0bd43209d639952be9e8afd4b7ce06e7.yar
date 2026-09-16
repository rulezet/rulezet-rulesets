rule sig_20160212_0bd43209d639952be9e8afd4b7ce06e7 {
  meta:
    description = "datamaliciousorder - file 20160212_0bd43209d639952be9e8afd4b7ce06e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "734af6653eed7151ca298d1b71feb9df353a05e1a7fe014d745ee44395b46815"

  strings:
    $s1 = "var a8='555C535E0D0A020B24011C1405101001070C4A070B095E3C5E0016010509070516030B4A160B5E17565E555051515652565157555E55',p80='); '," ascii
    $s2 = "; '+u43+g9+g59+' { l'+u86+p78+'; b'+'re'+y58+'}; } '+z96+'tch '+c12+'{ }; '+o19+';';this[s76](v56);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}