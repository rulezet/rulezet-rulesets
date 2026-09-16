rule sig_20160820_5e7055afbd11e022a2c5fe6fddf02e67 {
  meta:
    description = "datamaliciousorder - file 20160820_5e7055afbd11e022a2c5fe6fddf02e67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f5872074970a5d7b176359dfad6493cb7421e21084a5e0451323a605393e75"

  strings:
    $s1  = "var umgonel = new Array(\"19841\", \"wgehgalolpyr\", WScript, \"ejivilkihse\", \"10067\")[2];" fullword ascii
    $s2  = "var ebajyhf5 = new Array(\"15845\", \"10847\", 'Get', \"alajmyvyxzo\");" fullword ascii
    $s3  = "var vezjyre = new Array(788, \"oqopuqurru\", \"ororbibno\", \"axgenvimagmy\", \"tegetytek\");" fullword ascii
    $s4  = "var rehahzu1 = new Array(\"GET\", \"atubhoww\");" fullword ascii
    $s5  = "var ylyrzowsu4 = new Array(\"cmd\", \"dysypigb\", \"ivalydr\", \"10561\", \"omofjyttatdy\");" fullword ascii
    $s6  = "var urlynij5 = new Array(\"qpinyjazah\", \"us\", \"binkeco\", \"uchygjyn\");" fullword ascii
    $s7  = "var apmatxofa = new Array(\"23261\", \"23903\", \"http\");" fullword ascii
    $s8  = "var ywjojycomw0 = new Array(\"atwusbimgupe\", 'am', \"uqonizafgo\", \"ujdokgamx\");" fullword ascii
    $s9  = "var irqozrunalf6 = new Array(\"17070\", \"ics.\", \"jpyjvotkeg\");" fullword ascii
    $s10 = "var msupjumbenl8 = new Array('teFi', \"19816\", \"21881\");" fullword ascii
    $s11 = "var acmasumit8 = new Array(\"19638\", \"ti\");" fullword ascii
    $s12 = "function hzemhacmak() {" fullword ascii
    $s13 = "return yqqutc[0];" fullword ascii
    $s14 = "var ydicniq0 = new Array(\"24210\", \"17111\", \"20697\", \"23523\", \"MS\");" fullword ascii
    $s15 = "var dafdohsoxo0 = new Array(\"Fi\", \"iwuthucugve\", \"24720\", \"osnikrut\", \"20607\");" fullword ascii
    $s16 = "var yqqutc = new Array(\"Ar\", \"amcixobawg\", \"ublignuwsevu\");" fullword ascii
    $s17 = "var yposutbav9 = new Array('em', \"dtiqutgi\");" fullword ascii
    $s18 = "function ecdykonku() {" fullword ascii
    $s19 = "function acyp0() {" fullword ascii
    $s20 = "var ektacmuce = new Array(\"ekhicrewu\", \"ruqyhdawq\", \".ru/\", \"14534\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}