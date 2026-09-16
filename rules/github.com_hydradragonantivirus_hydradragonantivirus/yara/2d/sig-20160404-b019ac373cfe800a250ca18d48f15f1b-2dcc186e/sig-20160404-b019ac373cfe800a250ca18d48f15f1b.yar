rule sig_20160404_b019ac373cfe800a250ca18d48f15f1b {
  meta:
    description = "datamaliciousorder - file 20160404_b019ac373cfe800a250ca18d48f15f1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426b3e30164a2de989070f640a51a6238b7f7a087a726e19ccfba49732e80231"

  strings:
    $s1  = "return YtRXbIi[0] + YtRXbIi[2] + YtRXbIi[4] + \".F\" + YtRXbIi[7] + YtRXbIi[9] + YtRXbIi[12] + YtRXbIi[14];" fullword ascii
    $s2  = "var wl = true  , GPJy = VVP[7] + VVP[9] + VVP[11];" fullword ascii
    $s3  = "var YtRXbIi = YGWPq(KHUUgQzdBu+\" \"+\"System qK NxHdc Obj faFRKu ect YUOXdfQ KZSRj\", \" \");" fullword ascii
    $s4  = "var VVP = (\"2.XMLHTTP xCjPbOP JjXvw XML ream St offKvCCd AD hWttxuy O MiyI D\").split(\" \");" fullword ascii
    $s5  = "jvJX.open(NjQuY,iUODm,false);" fullword ascii
    $s6  = "if(z>=E.length) {break;}" fullword ascii
    $s7  = "function xNxYaIiph(FNRfU) {" fullword ascii
    $s8  = "function VRZz(tZFee) {" fullword ascii
    $s9  = "function sCMx(nYkQm) {" fullword ascii
    $s10 = "function wLrLa(OwPQBT) {" fullword ascii
    $s11 = "var olUYxkJ = \"DUGYJG*gcn*pt.S\"+\"hell*IZXlWIS*Scri*\";" fullword ascii
    $s12 = "return \"ZbjSXotrJKAYXi\";" fullword ascii
    $s13 = "function WIAFax(kYAQiXW) {" fullword ascii
    $s14 = "function zAVNt(KQaLDl) {" fullword ascii
    $s15 = "function FwVF(EFKuL) {" fullword ascii
    $s16 = "return Afd.split(rFKEb);" fullword ascii
    $s17 = "return dLS.size;" fullword ascii
    $s18 = "function YGWPq(Afd,rFKEb) {" fullword ascii
    $s19 = "function yFgOT(dJKdffJe,qeEH) {" fullword ascii
    $s20 = "return IKgVj.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}