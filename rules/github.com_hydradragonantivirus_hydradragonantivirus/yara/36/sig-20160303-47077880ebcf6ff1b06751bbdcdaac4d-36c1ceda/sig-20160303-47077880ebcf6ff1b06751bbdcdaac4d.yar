rule sig_20160303_47077880ebcf6ff1b06751bbdcdaac4d {
  meta:
    description = "datamaliciousorder - file 20160303_47077880ebcf6ff1b06751bbdcdaac4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42f2918e21ce30cffc0f1b614640535c3254d395ce5a436c1b06f0613f71677a"

  strings:
    $s1  = "var ONHfl = \"nIxYVC Jle pt.Shell NgOOJep Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var HFq = (qgb + \"TTP\" + \" MtQjhpJ HWHnc XML ream St BNYgmUje AD bXxbXla OD\").split(\" \");" fullword ascii
    $s3  = "return gzNkWGj[0] + gzNkWGj[2] + gzNkWGj[4] + \".F\" + gzNkWGj[7] + gzNkWGj[9] + gzNkWGj[12] + gzNkWGj[14];" fullword ascii
    $s4  = "var lI = true  , gKQd = HFq[7] + \"\" + HFq[9];" fullword ascii
    $s5  = "var gzNkWGj = \"Sc yTQtqGK r dWIufMmcQ ipting lsRzidM GJN ile gOnQDHoAJzeGXM System dG WMVMq Obj tqgzRE ect ecQkNSU\".split(\" " ascii
    $s6  = "TTxxz.open(yddzf,bzkuC,false);" fullword ascii
    $s7  = "if (CmSGY == 939-739){return true;} else {return false;}" fullword ascii
    $s8  = "tiZ = S; break; " fullword ascii
    $s9  = "function YsDnweA(zYoz) {" fullword ascii
    $s10 = "function PlOc(CmSGY) {" fullword ascii
    $s11 = "function IHzj(ijezI) {" fullword ascii
    $s12 = "function zrGF(yLRpZ,KOaSm) {" fullword ascii
    $s13 = "function UeAJasCkc(OZgqcVuHIpj) {" fullword ascii
    $s14 = "function UKoR(daXkD) {" fullword ascii
    $s15 = "function rqWdi(DliFTK) {" fullword ascii
    $s16 = "function vlrW(Djznk) {" fullword ascii
    $s17 = "return cHPiO;" fullword ascii
    $s18 = "return TRPl.responseBody;" fullword ascii
    $s19 = "if(S>=s.length) {break;}" fullword ascii
    $s20 = "function Vlhk(knTta) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}