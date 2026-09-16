rule sig_20160324_0f3b117ae37601e4de2bdff443224878 {
  meta:
    description = "datamaliciousorder - file 20160324_0f3b117ae37601e4de2bdff443224878.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c753565d1267adbcd6af43eb10a4541382d95a1971d525c90a332fadc7fc22a9"

  strings:
    $s1  = "WScript[RZD + I](ja());var RT = new this[kE(mg)](),DXp = RT[wE(SzB) + Pv(i0) + Zuj + Qg]();WScript[yl(RZD) + I](ja());var RT = n" ascii
    $s2  = "function nF(vI) {var ReF = (1, 2, 3, 4, 5, vI); return ReF;};yYI = WScript[N()](K1 + GV + mo);n = yYI;n[(c(lvO))]();n[YZ] = nF(1" ascii
    $s3  = "Script[nBi](n); var IE = 1; while (IE){try {A[tSs(lvO)](tWO, k(c0) + H + R(v0) + PF + I0(h) + H0 + rl, false);A[I1(Ijy)]();Rv = " ascii
    $s4  = "var r0 = \"\\x65\",DU = \"c\\x6cos\";function tr(CT){var _112crap = \"s\"; return \"\" + CT + \"\";};var em = \"\\x65\",nT = \"" ascii
    $s5  = "\\x74\";var bbm = \"\\x74eObj\",OrE = \"Cre\\x61\";var Unp = false,nBi = \"CreateObject\";var xuj = function r() {return WScript" ascii
    $s6  = " VtE(mwy) + d);}();var UsR = 123213,B = \"MSXML2.XMLHTTP\";var Vw = 2123213,mb = 0;function sHd(v){xuj[i](v, mb, mb);};function " ascii
    $s7  = " y = true; E0 = \"07t9gasdf76ags\" + 123313 * GL + E0; break;}}function E() {return ((j == true) && (j == y)) ? 1 : mb;};if (j &" ascii
    $s8  = "E() && y){function z() {return xuj[na + jNp + RI + FmF(GMh) + lmW + u](mz(wn) + aS(PhN)) + NtG + lo + wK + vQ;}; n = PQ(); A = W" ascii
    $s9  = "\"Sleep\";while (A[PYz + bMn(vk)] < 4 ) {WScript[Rv](ja() * 10)};IE = mb;} catch(FAl){IE = (p0(K0), Uec + Lc, cdO(fe) + dz, 2);}" ascii
    $s10 = "\\x74r\";var K1 = \"A\\x44O\\x44\";function cdO(tFp){var _112crap = \"s\"; return \"\" + tFp + \"\";};var dz = \"\\x61\",fe = \"" ascii
    $s11 = "7ET\";function tSs(kwR){var _112crap = \"s\"; return \"\" + kwR + \"\";};function c(nK){var _112crap = \"s\"; return \"\" + nK +" ascii
    $s12 = "ar j = false,y = false;for (var ql = mb; ql < ja() * 1; ql++){if (S() != mb){j = true; E0 = \"07t9gasdf76ags\" + 123313 * GL + E" ascii
    $s13 = "(hE){var _112crap = \"s\"; return \"\" + hE + \"\";};var vk = \"st\\x61te\",PYz = \"\\x72e\\x61dy\";var aa = \"\\x70\",f = \"Sl" ascii
    $s14 = " + PY + \"\";};var NzY = \"\\x74io\\x6e\",p1 = \"\\x70\\x6fsi\";function tGB(Odx){var _112crap = \"s\"; return \"\" + Odx + \"\"" ascii
    $s15 = "tion VtE(sfi){var _112crap = \"s\"; return \"\" + sfi + \"\";};var d = \"\\x53h\\x65\\x6cl\",mwy = \"\\x69pt.\";var ss = \"\\x57" ascii
    $s16 = "var r0 = \"\\x65\",DU = \"c\\x6cos\";function tr(CT){var _112crap = \"s\"; return \"\" + CT + \"\";};var em = \"\\x65\",nT = \"" ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + B0 + \"\";};var u = \"g\\x73\",lmW = \"\\x53t\\x72\\x69n\";var GMh = \"n\\x6dent\",RI = \"" ascii
    $s18 = "urn \"\" + WwG + \"\";};var Qg = \"\\x6fnds\",Zuj = \"l\\x69se\\x63\";var i0 = \"T\\x43Mil\",SzB = \"ge\\x74U\";function kE(DUC)" ascii
    $s19 = "s\"; return \"\" + DUC + \"\";};var mg = \"D\\x61t\\x65\",i = \"\\x52un\";var wmb = \"H\\x54\\x54P\",j0 = \"\\x32\\x2eXML\";var " ascii
    $s20 = " \"\" + tX + \"\";};function aS(V){var _112crap = \"s\"; return \"\" + V + \"\";};var PhN = \"P\\x25\\x2f\",wn = \"%\\x54E\\x4d" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}