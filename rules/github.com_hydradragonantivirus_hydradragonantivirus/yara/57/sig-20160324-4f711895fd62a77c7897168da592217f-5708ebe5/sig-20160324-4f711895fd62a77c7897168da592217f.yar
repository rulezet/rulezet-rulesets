rule sig_20160324_4f711895fd62a77c7897168da592217f {
  meta:
    description = "datamaliciousorder - file 20160324_4f711895fd62a77c7897168da592217f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af48240f120f5fba597e6b26014403d744c1521da9803a51d81e00b64bc0818b"

  strings:
    $s1  = "return WScript.CreateObject(QOaYY);" fullword ascii
    $s2  = "return nXrNvmk[0] + nXrNvmk[2] + nXrNvmk[4] + \".F\" + nXrNvmk[7] + nXrNvmk[9] + nXrNvmk[12] + nXrNvmk[14];" fullword ascii
    $s3  = "var Nz = true  , SWqf = Wpp[7] + Wpp[9] + Wpp[11];" fullword ascii
    $s4  = "var nXrNvmk = rQQsf(RqxVvRvZNG+\" \"+\"System gY MNyvQ Obj tuzymD ect OVGjmjo JJMwg\", \" \");" fullword ascii
    $s5  = "Gvcl.open(jxcfH,ZWNsO,false);" fullword ascii
    $s6  = "function yZxO(UXjbe,WqZer) {" fullword ascii
    $s7  = "function SZQmf(nAevup) {" fullword ascii
    $s8  = "function AbdQO(wKbTUq) {" fullword ascii
    $s9  = "function ufWV(qlkHw) {" fullword ascii
    $s10 = "return sqS.size;" fullword ascii
    $s11 = "return zdOc[oGNtom[0]];" fullword ascii
    $s12 = "function sXZP(UOYeK) {" fullword ascii
    $s13 = "return nAevup/*vzoJGPPMHjbGFSZsoTXQIRHwu*/.position=839-839;" fullword ascii
    $s14 = "return qlkHw.status;" fullword ascii
    $s15 = "function IVHW(vWRyS) {" fullword ascii
    $s16 = "function mCckyNx(zdOc) {" fullword ascii
    $s17 = "if (bqdcD > 163241-108){return true;} else {return false;}" fullword ascii
    $s18 = "function vrin(teNLX,ZWNsO,jxcfH) {" fullword ascii
    $s19 = "function xbEo(jXitx,NMill) {" fullword ascii
    $s20 = "return Aieg.ExpandEnvironmentStrings(ReMnG);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}