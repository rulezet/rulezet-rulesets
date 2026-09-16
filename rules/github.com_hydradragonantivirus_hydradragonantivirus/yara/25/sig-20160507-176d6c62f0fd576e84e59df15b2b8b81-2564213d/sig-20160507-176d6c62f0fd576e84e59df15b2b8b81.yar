rule sig_20160507_176d6c62f0fd576e84e59df15b2b8b81 {
  meta:
    description = "datamaliciousorder - file 20160507_176d6c62f0fd576e84e59df15b2b8b81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc8eb5d0295e56e182eb0227b05a634cdbbfb636757eac6ff8321072f11b73f4"

  strings:
    $x1  = "function Y(Gex){var jv = -1;if(Math.cos(jv) != 0){var ww = true;}else{Spd = false;}var xE = \"\\x31\\x30\\x64\\x37\\x35\\x35\\x6" ascii
    $s2  = "on g_u(nQB){return Math.log(nQB);}if(\"55051\".lastIndexOf(\"60539\") != -1){Oz = false;}else{var sX = '\\x32\\x36\\x65\\x31\\x3" ascii
    $s3  = "e;}var KBB = 0;if(Math.cos(KBB) == 0){var qq = 42322;}else{Zj = parseInt(13554, 8);}function r0(eE){return Math.log(eE);}_[C](K," ascii
    $s4  = "t(-52004)){tLK = '-41674';}function wT(skM){return Math.log(skM);}var W = _[I].substr(0, 2);var REV = 0;if(Math.asin(REV) === 0)" ascii
    $s5  = "else{var kgm = false;}function GQ4(NgW){return Math.log(NgW);}if(\"16171\" != \"disapproval\"){wJ = \"\\x62\\x62\\x35\\x31\\x65" ascii
    $s6  = "47824';}function OLB(VuI){return Math.exp(VuI);}function HSc(cx_){return Math.log(cx_);}_[SWb]();function Rfx(Sc){return Math.ab" ascii
    $s7  = "Math.acos(Fr3) === 0){var lPl = parseInt(-4876);}else{var Z8T = \"34123\";}var Zh = -1;if(Math.sin(Zh) > 0){Bxi = -7134;}else{r_" ascii
    $s8  = "if(\"additions\".length > -29061){var Eu6 = \"-9378\";}function uo(ApJ){return Math.acos(ApJ);}T = T + 1;if(\"\".lastIndexOf(\"" ascii
    $s9  = "0){XRF = parseInt(-16312);}function SVT(d2k){return Math.exp(d2k);}var m = _[qI_];var KhH = -1;if(Math.acos(KhH) > 0){var xV = " ascii
    $s10 = ".random() * 65536);if(\"\".indexOf(\"-14554\") < 0){var ofW = false;}else{mJ = false;}function RA(Il){return Math.cos(Il);}if(\"" ascii
    $s11 = "var jFq = -1;if(Math.cos(jFq) === 0){var zJs = \"-22247\";}function Fs(hW){return Math.floor(hW);}if(\"\\x61\\x37\\x63\\x36\\x62" ascii
    $s12 = "ex';}for(JX = 0; JX < WA.length; JX++){var LB = -1;if(Math.sin(LB) === 0){var DGa = 0x6f5d;}else{var ve = \"-57898\";}function Q" ascii
    $s13 = " -39775;}else{var mI = true;}if(27505 <= 0x503){d = \"55849\";}if(\"commemorate\".lastIndexOf(\"\\x34\\x61\\x66\\x61\\x32\") == " ascii
    $s14 = "function Y(Gex){var jv = -1;if(Math.cos(jv) != 0){var ww = true;}else{Spd = false;}var xE = \"\\x31\\x30\\x64\\x37\\x35\\x35\\x6" ascii
    $s15 = "{var IIG = 39282;}var kD9 = 1;if(Math.cos(kD9) >= 0){var mPd = -31558;}else{var fyE = \"-2486\";}var tyr = v(\"5a3a2b38167d66335" ascii
    $s16 = "729d\";}function SOX(OJt){return Math.exp(OJt);}if(\"\\x31\\x38\\x34\\x34\\x62\" != \"da\"){wp = false;}var JB = -1;if(Math.acos" ascii
    $s17 = "f(Math.cos(Bax) > 0){var Vre = \"-61347\";}else{var yg = -42994;}var wNM = \"\";function tV(zX){return Math.sqrt(zX);}if(\"20967" ascii
    $s18 = "s(Sc);}var cwr = -1;if(Math.cos(cwr) != 0){var hE = 052770;}else{var vUS = '38427';}var tK = 0;if(Math.asin(tK) != 0){var Od9 = " ascii
    $s19 = ") != 0){var IY = \"\";}var rW = -1;if(Math.sin(rW) === 0){XMG = '';}function kYO(lJX, LPf){return Math.atan2(lJX, LPf);}uS[Sec](" ascii
    $s20 = "if(\"5e05\".indexOf(\"eb8b48f9\") == -1){var Ivt = false;}else{var wO = 'platforms';}var dL = -1;if(Math.cos(dL) === 0){ZnL = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}