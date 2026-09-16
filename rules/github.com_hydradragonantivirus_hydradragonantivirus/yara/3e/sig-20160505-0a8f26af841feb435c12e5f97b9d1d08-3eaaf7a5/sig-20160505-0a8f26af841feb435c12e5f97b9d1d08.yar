rule sig_20160505_0a8f26af841feb435c12e5f97b9d1d08 {
  meta:
    description = "datamaliciousorder - file 20160505_0a8f26af841feb435c12e5f97b9d1d08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27d41d587bd07b018faa7b314260b4d06c181eddb461357217b01859ce90adfa"

  strings:
    $x1  = "function Qi(bKS){if(\"\\x32\\x64\\x61\\x36\\x61\\x39\".indexOf(\"-49009\") == -1){BQ = false;}else{var Q = \"\";}var ics = \"-41" ascii
    $s2  = "5v){Ew6 = -58291;}else{hS = \"-35428\";}function G_1(VG){return Math.log(VG);}for(rXe = 0; rXe < L.length; rXe++){var wZf = 1;if" ascii
    $s3  = "var YwY = true;}function VN(Ek){return Math.log(Ek);}if(parseInt(11111111111111111101101110100010, 2) != parseInt(11665, 8)){YB_" ascii
    $s4  = "{jn = \"-5079\";}if(parseInt(37777744232, 8) != parseInt(37777732230, 8)){cIF = '40173';}function kD(J3){return Math.log(J3);}if" ascii
    $s5  = "0\";if(nr != Yqu){var F4k = '';}var SB = AE7 + \"\\\\\" + wc4 + \".\" + cf4;var Hd = -1;if(Math.cos(Hd) != 0){_Ok = 23453;}else{" ascii
    $s6  = "66\\x34\\x32\\x33\".indexOf(\"e7aed7e\") != -1){var Jd = true;}var bOM = W1(\"2c202d\", \"key\");var bu = 1;if(Math.cos(bu) >= 0" ascii
    $s7  = "\"498\";}if(\"downloading\".lastIndexOf(\"\") != -1){RfT = \"\";}function C2W(eZs, eJ){return Math.atan2(eZs, eJ);}var WX = \"53" ascii
    $s8  = "if(Math.acos(eg) > 0){JL = 037777621127;}else{var EhK = false;}var b4 = -1;if(Math.cos(b4) >= 0){var uxM = \"reports\";}var Jqo " ascii
    $s9  = "\";}if(0xffff42f1 > parseInt(11111111111111111111010110001001, 2)){var xg = false;}var OC = -1;if(Math.sin(OC) > 0){var Wz7 = '-" ascii
    $s10 = "h.sin(MgO) > 0){var vR = parseInt(11111111111111111001010111111001, 2);}else{var INF = '-26916';}if(V == W1(\"263f\", \"key\")){" ascii
    $s11 = "= -10232;}else{Tu = \"b96fa\";}var wc4 = Math.floor(Math.random() * 65536);var WsS = 1;if(Math.acos(WsS) != 0){var dKH = parseIn" ascii
    $s12 = " = true;}return L;}function LZ(j, H){if(\"13375\".length === -15666){TM = '0a3c79e';}var kP = 1;if(Math.cos(kP) != 0){var f7e = " ascii
    $s13 = "b = true;}if(-2734 <= 012722){var Ze_ = -4205;}function ue(ITf){return Math.atan(ITf);}var yxp = W1(\"1811181f100a\", \"key\");f" ascii
    $s14 = "46701\";}else{var Lr = parseInt(-35341);}if(\"-46390\".length < -35106){var F0 = false;}var mz = W1(\"04151c05\", \"key\");if(\"" ascii
    $s15 = "se;}else{var C_I = 037777715057;}var Xc = -1;if(Math.cos(Xc) != 0){X3l = '-11051';}var Akp = 0;if(Math.acos(Akp) == 0){ViO = '-3" ascii
    $s16 = "= true;}else{var rp = \"130411\";}if(\"-2486\".length <= -43369){dfm = '';}var rff = 0;if(Math.sin(rff) != 0){var Sng = -19713;}" ascii
    $s17 = "rw = false;}var MaA = 0;if(Math.acos(MaA) > 0){var tUa = '';}var UEX = -1;if(Math.cos(UEX) >= 0){a = '';}else{kk = \"greenhouse" ascii
    $s18 = "= \"sexo\";}else{var G9P = '336';}var RI = -1;if(Math.sin(RI) == 0){var KN = '0d7f4e';}else{var dw = 'antechamber';}var Ii = 0;i" ascii
    $s19 = "62\".indexOf(\"\") == 0){var wUr = '';}else{var _J = true;}var MX = 1;if(Math.cos(MX) > 0){KCk = 24403;}PYi[F](p);var gMW = -1;i" ascii
    $s20 = "(\"baskets\".length >= -53709){rWv = false;}else{VGh = '31687';}var k2H = 0;if(Math.sin(k2H) > 0){var wRR = \"\";}if(\"-60038\"." ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}