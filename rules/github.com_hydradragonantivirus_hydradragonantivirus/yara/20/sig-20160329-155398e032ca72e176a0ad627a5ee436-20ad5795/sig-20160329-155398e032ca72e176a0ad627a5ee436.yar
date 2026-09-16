rule sig_20160329_155398e032ca72e176a0ad627a5ee436 {
  meta:
    description = "datamaliciousorder - file 20160329_155398e032ca72e176a0ad627a5ee436.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfa5101f9caec6c18bf48b83281ebc0529e55f405554493de65723506ef38e3e"

  strings:
    $s1  = "F[eg](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function Xp() {return r1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1r54vDZNq87N.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[D](xr() * 11); if (F[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var r1 = function Jy() {return WScript[Y](\"WScript.Shell\");}(), BH = 11;" fullword ascii
    $s5  = "function tx(j0, o){IK = IK * 1; return j0 - o;};" fullword ascii
    $s6  = "function X(){return \"\" + Cg;};" fullword ascii
    $s7  = "function r(j){r1[\"Run\"](j, IK, IK);};" fullword ascii
    $s8  = "function Q() {return ((G == true) && (G == E)) ? 1 : IK;};" fullword ascii
    $s9  = "return tx(Yq, R);" fullword ascii
    $s10 = "function Xw()" fullword ascii
    $s11 = "function gX(){return Y;};" fullword ascii
    $s12 = "var u = new this[\"Date\"]();" fullword ascii
    $s13 = "function A(AM) {var ZK = (1, 2, 3, 4, 5, AM); return ZK;};" fullword ascii
    $s14 = " while (Qb){" fullword ascii
    $s15 = "function xr(){return 22;};" fullword ascii
    $s16 = "E = true; " fullword ascii
    $s17 = "var J = false;" fullword ascii
    $s18 = "var G = false;" fullword ascii
    $s19 = "G = true; " fullword ascii
    $s20 = "} catch(s){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}