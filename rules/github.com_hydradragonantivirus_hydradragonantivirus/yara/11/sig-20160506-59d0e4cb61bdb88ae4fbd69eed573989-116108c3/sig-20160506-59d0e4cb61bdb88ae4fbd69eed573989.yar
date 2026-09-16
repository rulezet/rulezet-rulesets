rule sig_20160506_59d0e4cb61bdb88ae4fbd69eed573989 {
  meta:
    description = "datamaliciousorder - file 20160506_59d0e4cb61bdb88ae4fbd69eed573989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24eb648468ec089ab6edc098eacafebb666736ac09e45e668987ad9309c7f39e"

  strings:
    $s1  = "function C_O(){var NFM = 1;if(Math.cos(NFM) == 0){var TM = '-25099';}else{otM = '29252';}function s(lA){return Math.round(lA);}i" ascii
    $s2  = "n jG(wE){return Math.log(wE);}var BV = -1;if(Math.acos(BV) == 0){var Yzt = \"rings\";}else{I6V = 'nourish';}var xjv = sJr(\"5600" ascii
    $s3  = " pij = -1;if(Math.cos(pij) != 0){_3 = false;}else{var g1 = \"4e7c4a8d\";}continue;}if(\"clog\".lastIndexOf(\"828c3938\") > 0){FM" ascii
    $s4  = "LD = true;}if(6461 >= 053065){var fm = true;}function RF3(z0){return Math.log(z0);}if(\"3715\" === \"\\x39\\x34\\x66\\x62\\x35\"" ascii
    $s5  = "{KyN = -30059;}var knj = 0;if(Math.cos(knj) >= 0){iIw = 'scandinavian';}function Ytw(usX){return Math.ceil(usX);}var X7k = sJr(" ascii
    $s6  = "Math.atan2(Q3e, kzM);}mR[ZnR](P5i);var on = -1;if(Math.asin(on) >= 0){kC = true;}else{var jAb = \"20529\";}function _q(bWJ){retu" ascii
    $s7  = " VHy = -1;if(Math.sin(VHy) >= 0){vj = '';}var Pm = 0;if(Math.sin(Pm) == 0){var Fr = true;}else{x = false;}var nP = 0;if(Math.cos" ascii
    $s8  = "th.asin(sb) != 0){var ihU = 34081;}function Zl(qI_){return Math.sin(qI_);}var wU = -1;if(Math.cos(wU) >= 0){var Euk = false;}els" ascii
    $s9  = " = true;}mR[xjv]();var Vss = -1;if(Math.acos(Vss) >= 0){var MG = \"18707\";}else{var Jj = true;}function NEX(W_){return Math.sin" ascii
    $s10 = "r YzU = \"-27680\";if(X4 == YzU){var HU = true;}var rTQ = sJr(\"470725\", \"5rKYt2\");var DOQ = -1;if(Math.cos(DOQ) == 0){eBq = " ascii
    $s11 = "var Saj = -1;if(Math.sin(Saj) != 0){var Gbd = false;}else{var wA = '-57850';}var X7k = sJr(\"371711\", \"Rot8WJ\");}var sb = 0;i" ascii
    $s12 = "(\"\".lastIndexOf(\"58255\") == 0){var wd = 'b33128cb';}if(\"59160\".length >= -60841){eOt = false;}var kxz = -1;if(Math.cos(kxz" ascii
    $s13 = "ntuitive\" == \"24811\"){var _5h = \"-44969\";}else{ELD = \"acquisition\";}var ely = -1;if(Math.cos(ely) > 0){SM = \"58837\";}el" ascii
    $s14 = "5561c06055f3c2107\", \"ki7HUwxd\");var nZ = -1;if(Math.cos(nZ) == 0){_B = false;}var DCg = 1;if(Math.acos(DCg) == 0){var bsz = t" ascii
    $s15 = ";}var CYD = iLM(vX);function QW(Ro){return Math.tan(Ro);}var PY = 0;if(Math.cos(PY) == 0){var pD = -25841;}var THA = 1;if(Math.s" ascii
    $s16 = "cT = 1;if(Math.sin(cT) == 0){AkF = -34397;}var rI = \"\";if(rI != \"\\x31\\x36\\x31\\x63\\x35\\x63\\x35\"){var QQ = 037777603025" ascii
    $s17 = "= Z8[1];var zD = -1;if(Math.sin(zD) == 0){wF = 0xfffffb12;}else{EoN = '\\x63\\x31\\x34\\x32';}if(\"panel\".indexOf(\"\\x64\\x35" ascii
    $s18 = "\", \"xRl1M0rL\");var epX = 1;if(Math.acos(epX) > 0){jWm = '\\x32\\x64\\x35\\x33\\x32';}else{J_H = true;}var DhK = -1;if(Math.si" ascii
    $s19 = " > 0){var QR = \"\\x38\\x37\\x63\\x61\\x34\\x65\\x62\";}else{hu = \"-43771\";}var HY = 1;if(Math.cos(HY) > 0){nl = 3783;}var TN " ascii
    $s20 = "h.cos(aK) >= 0){s3 = \"10965\";}if(\"ae52\".length >= 0xffff9ae8){var l = true;}if(\"ad3d97e\".length != -16166){UQC = \"wrappin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}