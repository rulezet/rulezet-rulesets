rule sig_20160506_28649de98c56da698ecf00982a2749f3 {
  meta:
    description = "datamaliciousorder - file 20160506_28649de98c56da698ecf00982a2749f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d5e28a4ad2856970e733a8d92ad3ee6dc16a21f83d1e3a30ff7e49eecd3e85a"

  strings:
    $s1  = "function B(){if(parseInt(-8838) < 0xffff07d1){var Bh = true;}if(\"34935\".indexOf(\"f2d68a1d\") != -1){BN = false;}else{gF = par" ascii
    $s2  = "){qzr = \"3c88c1d\";}else{cP = parseInt(41064);}function _oy(Dr){return Math.log(Dr);}var iz = -1;if(Math.cos(iz) >= 0){yXE = ''" ascii
    $s3  = "399\") == -1){var rnz = true;}var jb = 1;if(Math.sin(jb) != 0){var Nq = '49034';}Ki = Ki + 1;if(\"animation\".indexOf(\"-33255\"" ascii
    $s4  = "A = true;}if(\"\\x38\\x35\\x37\\x36\".indexOf(\"\") == 0){yc = false;}else{var qkR = \"removable\";}UD[nP]();var aNv = -1;if(Mat" ascii
    $s5  = "r Up = 0;if(Math.cos(Up) === 0){var qju = false;}var D = -1;if(Math.sin(D) === 0){var SXa = true;}var zz = 0;if(Math.cos(zz) ===" ascii
    $s6  = "){_0 = \"ef77f8\";}var J = -1;if(Math.acos(J) === 0){var eNL = 28872;}else{var FQ2 = \"\";}function Fz(s9){return Math.exp(s9);}" ascii
    $s7  = "= -1){Y = false;}var A = Bz[l].split(\"|\");var WNE = 0;if(Math.sin(WNE) === 0){var yxp = \"fff3757\";}else{W8R = \"e633e\";}fun" ascii
    $s8  = " != 0){Jht = true;}if(bfX == kA(\"3a13\", \"wI37Dd1v\")){function ue_(zAo){return Math.cos(zAo);}var Swv = -1;if(Math.sin(Swv) =" ascii
    $s9  = " 0){uXN = \"2b0fe1a\";}var qA = -1;if(Math.sin(qA) != 0){EJZ = 48682;}var _j = \"\";if(_j === \"wisp\"){var Fbs = \"excellent\";" ascii
    $s10 = "){wF = 0153242;}else{EoN = '53afd';}if(\"-31169\" == \"0747\"){var QR = \"be6a15f7\";}var ZF = -1;if(Math.sin(ZF) > 0){nl = 4648" ascii
    $s11 = "1c == -53721){uAm = true;}else{rH = '-45911';}var Q3 = 1;if(Math.cos(Q3) > 0){var VKq = parseInt(-2444);}else{C4 = parseInt(-594" ascii
    $s12 = "{var rCP = \"7457\";}var qe1 = \"c3570da\";if(qe1 == \"ebdc056d\"){var v1d = \"55590\";}else{var JUC = 0104737;}var zPp = -1;if(" ascii
    $s13 = "th.sin(iWl);}UD[mtp] = 1;if(\"42412\".lastIndexOf(\"18933\") == -1){c3F = \"spice\";}else{veY = 037777752034;}if(\"796a136\".len" ascii
    $s14 = "fff909d;}else{yfp = 'daa5e51';}var fJ = -1;if(Math.acos(fJ) === 0){oA = '5e66';}else{var xRJ = true;}var fk = 0;if(Math.sin(fk) " ascii
    $s15 = "}else{ZNi = true;}var sb = 0;if(Math.cos(sb) === 0){wbe = false;}else{UnQ = '';}var UD = k37(GNP);var xa4 = -1;if(Math.acos(xa4)" ascii
    $s16 = "e9b\";}if(-63995 == 24307){var Y6 = true;}else{Dm = false;}var bDF = kA(\"5e425227\", \"127It9JG\");var hr2 = -1;if(Math.cos(hr2" ascii
    $s17 = "if(Math.sin(Am) != 0){var EWi = true;}var EM = kA(\"040f26262019050f37392b0e\", \"vjUVOw\");var cR = -1;if(Math.acos(cR) != 0){v" ascii
    $s18 = "X) != 0){WT = '62150';}else{var deV = 0x890;}Ki = 0;}}function na(mNM){return Math.exp(mNM);}var Uoq = -1;if(Math.cos(Uoq) === 0" ascii
    $s19 = "lse{io = true;}var Dnw = -1;if(Math.sin(Dnw) != 0){var XV = 'f248c1b';}return ss;}B();" fullword ascii
    $s20 = "kR(Y6M){return Math.floor(Y6M);}var fy = -1;if(Math.sin(fy) === 0){var iv = false;}if(\"-22906\".lastIndexOf(\"859bf\") < 0){var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}