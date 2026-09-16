rule sig_20160505_ff4c6f7a1eb04edfcdcbd4d131e907cf {
  meta:
    description = "datamaliciousorder - file 20160505_ff4c6f7a1eb04edfcdcbd4d131e907cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141a5349b576f1566b78eda4fc50192fa4b97d99e0cfa800df1a26da22cefabb"

  strings:
    $x1  = "function N(){var HJ = \"\\x35\\x61\\x32\\x30\\x33\";if(HJ != \"\\x30\\x31\\x61\\x30\\x36\\x38\"){Pjw = '';}else{Vtq = true;}func" ascii
    $s2  = "\\x38\";}if(\"44366\".length === -16003){var sq = parseInt(-26717);}O = 0;}}function PZ(Yt1){return Math.log(Yt1);}if(\"-59253\"" ascii
    $s3  = "nction Ji(eAH){return Math.log(eAH);}var vQ = 1;if(Math.acos(vQ) >= 0){JMS = 0xffffd6d7;}else{D1L = \"sawdust\";}if(\"\".lastInd" ascii
    $s4  = "= \"63705\";}function Hrr(kL){return Math.acos(kL);}function GtR(_B){return Math.log(_B);}function qh5(f6x){return Math.ceil(f6x" ascii
    $s5  = "b451d14070d0d1f15\", \"key\");var Df = -1;if(Math.sin(Df) > 0){dGd = true;}var bzb = 0;if(Math.asin(bzb) === 0){var _qT = \"\\x3" ascii
    $s6  = "= '43e9ff';}var S = vuH(\"1811181f100a\", \"key\");var hQ = -1;if(Math.sin(hQ) != 0){u2 = false;}else{var lp = \"9026\";}if(\"-9" ascii
    $s7  = "Math.exp(z);}if(\"520b\".length >= parseInt(1010110000100010, 2)){W = \"amy\";}else{LaX = true;}var hA = -1;if(Math.acos(hA) ===" ascii
    $s8  = "nt(-15176)){dn = \"attempted\";}else{var RU = '-21753';}var qHI = 0;if(Math.acos(qHI) == 0){var nc = 0xffff1a55;}var p = e[nV].s" ascii
    $s9  = "ar GlY = -1;if(Math.sin(GlY) > 0){var mM = '733bf406';}else{var bGh = \"-8868\";}if(parseInt(11111111111111110011010100100101, 2" ascii
    $s10 = "){var TyO = parseInt(11111111111111111101011011110100, 2);}else{var kv = \"770\";}var ViO = -1;if(Math.sin(ViO) >= 0){V_ = false" ascii
    $s11 = "a(bxb){return Math.asin(bxb);}var a = jx + \"\\\\\" + mW + \".\" + lj;if(\"4285\".lastIndexOf(\"crusade\") != -1){hK = '\\x38\\x" ascii
    $s12 = "= \"4da9f2\";if(tW == \"31720\"){var EJZ = 'anthropology';}else{var R_m = true;}var u = vuH(\"0a01160f075718110b0e0414\", \"key" ascii
    $s13 = "';}if(\"\" != \"passed\"){var _N = '';}if(parseInt(11111111111111110001100100101100, 2) < 0x3250){var CC = \"remote\";}else{var " ascii
    $s14 = " 'colder';}var x = Cek(SJ1);if(\"measurement\" != \"42984\"){var gi = \"scanned\";}else{gl = \"corpus\";}var zUv = 1;if(Math.sin" ascii
    $s15 = "c150e\", \"key\");var yxD = -1;if(Math.asin(yxD) > 0){var RiY = true;}var FkJ = 1;if(Math.acos(FkJ) === 0){var EUj = \"\\x30\\x3" ascii
    $s16 = "lse;}else{_s = true;}var pn = -1;if(Math.cos(pn) >= 0){a0Q = \"aba627e6\";}else{var uL = '';}if(\"-48847\".length < 0x1b5c){Dlo " ascii
    $s17 = "485\".lastIndexOf(\"incompatible\") == -1){var GNy = \"\";}else{var NQ = 0xffff39b5;}var J1k = 0;if(Math.acos(J1k) != 0){var Q4 " ascii
    $s18 = "'valuation';}else{var Qcl = false;}var OGK = -1;if(Math.asin(OGK) === 0){In = \"unlock\";}var sV9 = 1;if(Math.cos(sV9) > 0){wZ9 " ascii
    $s19 = ".exp(S45);}var fX_ = -1;if(Math.sin(fX_) === 0){Wtf = -23849;}return(EOf);}function vuH(ylO, YF){if(\"\".lastIndexOf(\"\\x34\\x3" ascii
    $s20 = "== -1){qi = \"d8c8a\";}var aPa = 1;if(Math.sin(aPa) >= 0){var RsX = true;}var A3B = 1;if(Math.asin(A3B) === 0){lzK = true;}var t" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}