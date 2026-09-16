rule sig_20160311_20e0528d0cb4833ffe6b67a034a9b27a {
  meta:
    description = "datamaliciousorder - file 20160311_20e0528d0cb4833ffe6b67a034a9b27a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a41bc875a4f63324d5ae9984fd26c08ff97869fba6a9387c84dfcd936bf56e5e"

  strings:
    $s1  = "return FZhUbUG[0] + FZhUbUG[2] + FZhUbUG[4] + \".F\" + FZhUbUG[7] + FZhUbUG[9] + FZhUbUG[12] + FZhUbUG[14];" fullword ascii
    $s2  = "var zL = true  , xZOY = fcu[7] + fcu[9] + fcu[11];" fullword ascii
    $s3  = "var FZhUbUG = \"Sc ZlPkATH r VvsIDcNCN ipting VYUhgWP rUE ile aUujfFrZBUHUWx System WT KiAgk Obj qrrtej ect sswxMXv\".split(\" " ascii
    $s4  = "sIaFd.open(DxbrB,claoH,false);" fullword ascii
    $s5  = "var fcu = (\"2.XMLHTTP FFOOyhU zaIiB XML ream St EngaaCxg AD IRmKdcK O YIfS D\").split(\" \");" fullword ascii
    $s6  = "function hvWaESn(tbDg,zvKMt) {" fullword ascii
    $s7  = "function vNcD(wuGsh) {" fullword ascii
    $s8  = "function kmRK(vaGYF) {" fullword ascii
    $s9  = "return lEVcC;" fullword ascii
    $s10 = "function ZGsU(HqHAv,bCoxy) {" fullword ascii
    $s11 = "return XVJDtfu" fullword ascii
    $s12 = "function XNfPAvRY(CTpAL,EkPSmo) {" fullword ascii
    $s13 = "return BfFFZv.position=272-272;" fullword ascii
    $s14 = "function AkeiOWfea() {" fullword ascii
    $s15 = "return hvWaESn(ju,QBmYw[312-306]+QBmYw[942-935]+QBmYw[523-515]);" fullword ascii
    $s16 = "return tbDg.ExpandEnvironmentStrings(zvKMt);" fullword ascii
    $s17 = "if (aEgUc > 129027-812){return true;} else {return false;}" fullword ascii
    $s18 = "function RiBf(NbVAP,KbApa) {" fullword ascii
    $s19 = "function pjkqD(eaDjsC) {" fullword ascii
    $s20 = "function Nrxt(gIcjp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}