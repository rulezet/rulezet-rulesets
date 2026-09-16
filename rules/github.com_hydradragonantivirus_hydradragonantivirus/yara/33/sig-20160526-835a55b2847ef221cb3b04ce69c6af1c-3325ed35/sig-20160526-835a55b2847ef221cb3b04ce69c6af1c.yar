rule sig_20160526_835a55b2847ef221cb3b04ce69c6af1c {
  meta:
    description = "datamaliciousorder - file 20160526_835a55b2847ef221cb3b04ce69c6af1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42a3d4b672c9315b64b1aec15f94aea21288dad986718757652a3b5e168faf62"

  strings:
    $s1  = "ath.cos(420), 2) - 1))-498)) JauBeUH += vB(gBWKXYdWjwU);else if (MBCWjqefLyDSXykLKmubcsM == (325 + Math.round((Math.pow(Math.sin" ascii
    $s2  = "(753), 2) + Math.pow(Math.cos(753), 2) - 1))-261)) JauBeUH += HRlajXgquqIi(gBWKXYdWjwU, nruoCtnmeSsnAgbaw);else JauBeUH += unYou" ascii
    $s3  = "function HTwVbY(uIsovcnRoSqgi) {var bTBDBdwyPDSEomeDVm = vFErYEb.join(dOdtxlsdPSDmHQxKuRcVbJ[0]);var gBWKXYdWjwU, nruoCtnmeSsnAg" ascii
    $s4  = "function UnCabrwWU(KcxqFjszUgRGcHDzesyzf,LzXqknavjgsRFbwLseT){return KcxqFjszUgRGcHDzesyzf.charAt(LzXqknavjgsRFbwLseT);}" fullword ascii
    $s5  = "function HRlajXgquqIi(pkZvRwCQvAfq,nEPumIvG){return String.fromCharCode(pkZvRwCQvAfq,nEPumIvG);}" fullword ascii
    $s6  = "Pb(gBWKXYdWjwU, nruoCtnmeSsnAgbaw, iwQkUzWycQZvtxZJBAJxkUi);} while (bFScIcrkyxDRTrYYwRbKO < uIsovcnRoSqgi.length);return JauBeU" ascii
    $s7  = "function vB(yyifXWBRzZ){return String.fromCharCode(yyifXWBRzZ);}" fullword ascii
    $s8  = "function HTwVbY(uIsovcnRoSqgi) {var bTBDBdwyPDSEomeDVm = vFErYEb.join(dOdtxlsdPSDmHQxKuRcVbJ[0]);var gBWKXYdWjwU, nruoCtnmeSsnAg" ascii
    $s9  = "function vEqvaeseEQLdh(TJsazMGpQjpMKcCNZp,ZMKYEBwMUloCprd){return TJsazMGpQjpMKcCNZp.indexOf(ZMKYEBwMUloCprd);}" fullword ascii
    $s10 = "function unYouPb(rIlKvyQOohqOEllcAPBWx,EXATJSEVVKlXTi,nyyBAZGpLOqhAFoOeczXkVd){return String.fromCharCode(rIlKvyQOohqOEllcAPBWx," ascii
    $s11 = "function unYouPb(rIlKvyQOohqOEllcAPBWx,EXATJSEVVKlXTi,nyyBAZGpLOqhAFoOeczXkVd){return String.fromCharCode(rIlKvyQOohqOEllcAPBWx," ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}