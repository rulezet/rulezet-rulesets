rule sig_20160313_a1b9b39439431d50fc6459343ce21fff {
  meta:
    description = "datamaliciousorder - file 20160313_a1b9b39439431d50fc6459343ce21fff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ff9765393e6f6b4e66a37803f8a05eb33826573b1cae0921034696985e57b99"

  strings:
    $s1  = "function gEeltBgPH(ocLogNvOqGm) {" fullword ascii
    $s2  = "return YGXitfK[0] + YGXitfK[2] + YGXitfK[4] + \".F\" + YGXitfK[7] + YGXitfK[9] + YGXitfK[12] + YGXitfK[14];" fullword ascii
    $s3  = "var ti = true  , yUXn = Say[7] + Say[9] + Say[11];" fullword ascii
    $s4  = "var YGXitfK = \"Sc MQfJupC r axhWtxYVa ipting ihhYAQX EnZ ile FBjvxROogZDHqh System ft kOBKN Obj PaaBvI ect iULzRct\".split(\" " ascii
    $s5  = "var Say = (\"2.XMLHTTP gKxyQko LjyJX XML ream St LFdGAoVk AD qMEImNj O ovHS D\").split(\" \");" fullword ascii
    $s6  = "ovrma.open(iBrjp,ulnAZ,false);" fullword ascii
    $s7  = "function AFrVU(lyueTQ) {" fullword ascii
    $s8  = "function zPBur(TsBbyP) {" fullword ascii
    $s9  = "if (GMuSB == 555-355){return true;} else {return false;}" fullword ascii
    $s10 = "return JKBA.ExpandEnvironmentStrings(AsYdT);" fullword ascii
    $s11 = "function VBSf(zBITW) {" fullword ascii
    $s12 = "function HPWX(ovrma,ulnAZ,iBrjp) {" fullword ascii
    $s13 = "function kzvUEEw(JKBA,AsYdT) {" fullword ascii
    $s14 = "if(R>=O.length) {break;}" fullword ascii
    $s15 = "return EFYaO.status;" fullword ascii
    $s16 = "yEO = R; break; " fullword ascii
    $s17 = "return ZUh.size;" fullword ascii
    $s18 = "function jxYh(NllDU,pMswM) {" fullword ascii
    $s19 = "return kzvUEEw(eg,FwdRi[377-371]+FwdRi[503-496]+FwdRi[439-431]);" fullword ascii
    $s20 = "function HnXi(BzCIN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}