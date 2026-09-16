rule sig_20160507_0347df5b6b1c82c06ef10dba3756d37d {
  meta:
    description = "datamaliciousorder - file 20160507_0347df5b6b1c82c06ef10dba3756d37d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dfd6ba17ee333bcf7aa5266b9189445ae4630692b38614a01fa37fa7e0a3d86"

  strings:
    $s1  = "function SFb(){var THO = \"\";if(THO === \"65388\"){var F = \"\\x32\\x37\\x62\\x34\\x63\";}if(\"-11850\" != \"\\x37\\x63\\x61\\x" ascii
    $s2  = "R = \"-28242\";}var k9q = 0;if(Math.acos(k9q) >= 0){var niy = \"recommended\";}function _G4(M4){return Math.log(M4);}if(\"\\x35" ascii
    $s3  = "();function VUR(aNv){return Math.sin(aNv);}function mDA(Mdq){return Math.ceil(Mdq);}function EPy(wPn){return Math.log(wPn);}if(" ascii
    $s4  = ";if(Nk1 != \"12167\"){var yVS = '\\x36\\x65\\x63\\x33\\x66\\x66\\x30\\x63';}else{var Mh = false;}function sWZ(jyb){return Math.l" ascii
    $s5  = "(eZZ){return Math.log(eZZ);}if(\"-39958\" == \"\"){O8 = \"\\x61\\x63\\x65\\x32\\x31\\x33\\x61\\x66\";}else{PbC = true;}if(\"reco" ascii
    $s6  = "73;}function yN(vix){return Math.log(vix);}var kc = \"\\x30\\x37\\x66\\x32\\x64\\x38\\x64\\x62\";if(kc != \"mew\"){_Mw = false;}" ascii
    $s7  = "arseInt(-60484);}else{MDq = '14093';}function ADK(cHt){return Math.log(cHt);}var Dn = \"pair\";if(Dn === \"\"){var zVS = parseIn" ascii
    $s8  = "var THj = 'gr';}finally{xBm = '-54091';}var V = Xc + \"\\\\\" + mO + \".\" + bJ;var u8x = 1;if(Math.asin(u8x) != 0){var rCF = -3" ascii
    $s9  = "r q = -21057;}if(30400 === parseInt(-21048)){var jM = \"turbid\";}else{M = \"well-fed\";}var mO = Math.floor(Math.random() * 655" ascii
    $s10 = "var RFJ = 0;if(Math.sin(RFJ) != 0){BK = 'tuscan';}else{var t6 = -65522;}if(\"a715ec3\" == \"-5275\"){BSy = \"32963\";}else{g_T =" ascii
    $s11 = "f5){YXe = \"\";}else{cS = 63092;}Vj = Vj + 1;function RJ(vYY){return Math.tan(vYY);}if(parseInt(123707, 8) != 0xffff9286){_IP = " ascii
    $s12 = "On = -63266;}var HQ = VP[3];function Kk(OV){return Math.exp(OV);}function oF(tI){return Math.sqrt(tI);}var ki = 1;if(Math.asin(k" ascii
    $s13 = "offensive\";}var Fw = \"-16495\";if(Fw === \"phrases\"){var iG = \"\";}else{WG = parseInt(-24159);}var QPT = -1;if(Math.sin(QPT)" ascii
    $s14 = "x34\\x34\\x30\\x61\\x66\".lastIndexOf(\"muss\") != -1){nz = 5596;}var YlP = -1;if(Math.sin(YlP) === 0){var xg = true;}function O" ascii
    $s15 = "}var Z = new Array();var C7 = -1;if(Math.sin(C7) == 0){var ms = false;}else{E87 = true;}var q0U = 0;if(Math.acos(q0U) === 0){mwU" ascii
    $s16 = "if(\"\\x39\\x39\\x37\\x66\\x61\\x64\\x64\\x62\".length >= -33214){su = '';}var grf = 0;if(Math.sin(grf) >= 0){var nv = false;}el" ascii
    $s17 = "r(0, 2);var GXp = 0;if(Math.acos(GXp) != 0){a8y = \"04781d2\";}var gi = -1;if(Math.cos(gi) === 0){var APy = 0x5fe6;}else{sFl = f" ascii
    $s18 = "ar HA = \"\\x63\\x34\\x66\\x35\";}var m2J = -1;if(Math.sin(m2J) >= 0){VQ = \"-13950\";}else{var uC = '\\x35\\x37\\x37\\x34\\x62" ascii
    $s19 = "4)){var IXI = \"7f50\";}if(\"-59773\" != \"coverage\"){WS = -46053;}else{rZv = '0e7adb';}var K4z = -1;if(Math.cos(K4z) === 0){va" ascii
    $s20 = "ound(uHY);}var hr2 = -1;if(Math.sin(hr2) > 0){Qbq = false;}var xzf = -1;if(Math.asin(xzf) > 0){var d2 = '';}for(ge = 0; ge < AqG" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}