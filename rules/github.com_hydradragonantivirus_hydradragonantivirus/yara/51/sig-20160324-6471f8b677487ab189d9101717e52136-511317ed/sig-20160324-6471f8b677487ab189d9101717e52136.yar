rule sig_20160324_6471f8b677487ab189d9101717e52136 {
  meta:
    description = "datamaliciousorder - file 20160324_6471f8b677487ab189d9101717e52136.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99c86cd5224ace9c0934b18d0750a37f697ae8c616820ef483130587cfb36ab6"

  strings:
    $s1  = "var S = \"\\x65\",o = \"\\x63l\\x6fs\";function MR(uFT){var _112crap = \"s\"; return \"\" + uFT + \"\";};var tYs = \"\\x65\",Zgp" ascii
    $s2  = "ei = G[V0 + lm + rA + I(e1)]();WScript[s + YM](u());var G = new this[oG](),q = G[i(V0) + lm + rA + e1]();var wl = \"F\";wl = yod" ascii
    $s3  = "), Sad + BS + t1(lP) + IDB + ElM(lJ) + Ml, false);SoA[NvK]();XIC = \"Sleep\";while (SoA[IaR + WXq + rvF(Uq)] < 4 ) {WScript[XIC]" ascii
    $s4  = "l = 0,rX = 0;function hK(){var G = new this[oG](),hFl = G[V0 + MPC(lm) + rA + e1]();WScript[s + YM](u());var G = new this[oG]()," ascii
    $s5  = "+ GZr(RGw) + JIB + Qk + PEj](sJ + RP) + TsK + z + Gg;}; vo = A(); SoA = WScript[Cs](vo); var t = 1; while (t){try {SoA[x](Ts(hK0" ascii
    $s6  = "Script[V()](WQO + h + RJT);vo = WOS;vo[(LX(x))]();vo[FCh] = Cq(1);vo[l + dD](SoA[x0 + MqK(T0) + sf]);vo[UF + aH(J1)] = Cq(xbS);v" ascii
    $s7  = "68.n\\x65\",lP = \"ch\\x75r\\x63\";var BS = \"\\x2f/mqh\",Sad = \"\\x68ttp:\";function Ts(P0){var _112crap = \"s\"; return \"\" " ascii
    $s8  = "3re\\x61t\",Tq = false;var Cs = \"CreateObject\",Hhx = function iY() {return WScript[Cs](A0 + Qy + HT);}();var uI = 123213,X = " ascii
    $s9  = "}function TT() {return ((PPF == true) && (PPF == Cxt)) ? 1 : xbS;};if (PPF && TT() && Cxt){function GRE() {return Hhx[yrG + NmS " ascii
    $s10 = " cdI = \"\\x53aveT\";function aH(s0){var _112crap = \"s\"; return \"\" + s0 + \"\";};var J1 = \"t\\x69on\",UF = \"\\x70\\x6f\\x7" ascii
    $s11 = "hK() != xbS){PPF = true; rX = \"07t9gasdf76ags\" + 123313 * wl + rX; Cxt = true; rX = \"07t9gasdf76ags\" + 123313 * wl + rX; bre" ascii
    $s12 = " return \"\" + nj + \"\";};function ElM(zG){var _112crap = \"s\"; return \"\" + zG + \"\";};var Ml = \"\\x73y\",lJ = \"t/\\x6b2u" ascii
    $s13 = " \"\";};function i(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};var e1 = \"o\\x6eds\",rA = \"lis\\x65c\";var lm = \"T\\x43M" ascii
    $s14 = ",TsK = \"B\\x6a\\x45cj\";var RP = \"P\\x25/\",sJ = \"\\x25T\\x45M\";function GZr(lB){var _112crap = \"s\"; return \"\" + lB + \"" ascii
    $s15 = "hK0 = \"G\\x45\\x54\";function LX(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};var x = \"o\\x70en\",Gg = \".\\x65xe\";var z" ascii
    $s16 = "\";var jP = \"\\x61sdf\",tO = \"\\x66a\\x64f\";var A2 = \"asd\\x66a\";function rvF(f0){var _112crap = \"s\"; return \"\" + f0 + " ascii
    $s17 = "var S = \"\\x65\",o = \"\\x63l\\x6fs\";function MR(uFT){var _112crap = \"s\"; return \"\" + uFT + \"\";};var tYs = \"\\x65\",Zgp" ascii
    $s18 = "(R){var _112crap = \"s\"; return \"\" + R + \"\";};var sf = \"\\x42ody\",T0 = \"on\\x73e\";var x0 = \"\\x52\\x65sp\",dD = \"\\x6" ascii
    $s19 = "\",s = \"S\\x6cee\";function MPC(NHb){var _112crap = \"s\"; return \"\" + NHb + \"\";};function I(A1){var _112crap = \"s\"; retu" ascii
    $s20 = "i, hFl);var rX = \"J\";rX = yod(q, ei);return yod(wl, rX);}var PPF = false,Cxt = false;for (var kA = xbS; kA < u() * 1; kA++){if" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}