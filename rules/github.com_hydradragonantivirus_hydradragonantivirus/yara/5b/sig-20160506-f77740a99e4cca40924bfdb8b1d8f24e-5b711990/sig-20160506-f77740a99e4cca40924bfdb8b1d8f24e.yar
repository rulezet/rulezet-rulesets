rule sig_20160506_f77740a99e4cca40924bfdb8b1d8f24e {
  meta:
    description = "datamaliciousorder - file 20160506_f77740a99e4cca40924bfdb8b1d8f24e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5fe6a3c100389ebd22fffe3ca0058bd3c651296cf05ae8215dfca3a8edb7362"

  strings:
    $x1  = "function F(b, j){if(\"\\x33\\x65\\x64\\x65\\x33\\x66\\x61\\x66\" == \"\"){JS = '';}if(-9153 === parseInt(-48995)){var zfM = \"\"" ascii
    $s2  = "= 0;if(Math.sin(wyv) != 0){var m6 = -32554;}else{Qw = false;}continue;}function Ouj(xe){return Math.log(xe);}var qh = 0;if(Math." ascii
    $s3  = "nt(-61199)){var gGl = 'targets';}return(RP);}function qzq(Z){var GA5 = 0;if(Math.cos(GA5) >= 0){var p2 = \"pissing\";}else{ok = " ascii
    $s4  = "h.log(LX9);}var qY = 0;if(Math.cos(qY) === 0){TIJ = false;}var kul = kxN[e].split(\"|\");var ASz = 0;if(Math.acos(ASz) == 0){WsS" ascii
    $s5  = "ath.cos(cUx) >= 0){var hM = 0113254;}if(\"duties\".lastIndexOf(\"\\x39\\x65\\x66\\x37\\x65\\x30\\x33\") == -1){var QAY = \"322f" ascii
    $s6  = "\\x64\\x64\\x31\\x34\"){Nge = false;}var JQQ = DQ + \"\\\\\" + zbW + \".\" + EJm;function Cp0(FWq){return Math.round(FWq);}try{Z" ascii
    $s7  = " '44129';}if(ew == F(\"1e2e\", \"StDoynWq\")){var fU = 0;if(Math.cos(fU) != 0){var RiY = true;}var iuO = -1;if(Math.acos(iuO) ==" ascii
    $s8  = " = false;}if(0xfffff68e < parseInt(-44067)){HJ = 42747;}else{var G3 = \"27677\";}cK[ATN] = 1;var aEh = -1;if(Math.cos(aEh) === 0" ascii
    $s9  = "47b0c140e26720d4564155c\", \"kZC49Uil\");var DKH = -1;if(Math.cos(DKH) >= 0){var po0 = -42234;}else{ta = false;}if(0xffff1d86 !=" ascii
    $s10 = "Wg = -1;if(Math.cos(DWg) === 0){Q = 28413;}else{iW = 'a047';}var JAf = -1;if(Math.asin(JAf) === 0){WtI = -60878;}var Hna = \"not" ascii
    $s11 = "== -1){var FMZ = -19342;}var ngg = -1;if(Math.sin(ngg) == 0){var O9 = 'wright';}else{zh = '\\x62\\x33\\x31\\x66\\x66\\x31';}var " ascii
    $s12 = "}if(n == 0){if(\"24597\".length != -14921){var pn = '';}else{aKt = '-1665';}var LWQ = 0;if(Math.cos(LWQ) === 0){Gp = true;}var l" ascii
    $s13 = "= '';}var r3 = -1;if(Math.cos(r3) == 0){var Sd = true;}if(parseInt(37777606370, 8) <= parseInt(39849)){Gkb = true;}else{J = '\\x" ascii
    $s14 = ";}if(\"54070\".indexOf(\"\\x66\\x37\\x38\\x30\\x35\\x35\\x61\") == 0){gKI = \"507\";}else{hNP = parseInt(47738);}var Ob = -1;if(" ascii
    $s15 = "se{var VuI = -33130;}if(\"\".indexOf(\"32613\") == -1){mj = '-44076';}var Tga = 1;if(Math.sin(Tga) === 0){Lci = true;}var XUT = " ascii
    $s16 = "h.cos(m_) > 0){wO = false;}else{var pW = \"-5254\";}if(52711 === 0xffff6ee7){var ony = 'norm';}if(-4788 <= -24107){lW4 = \"-2345" ascii
    $s17 = "turn Math.ceil(DS8);}var Ghg = -1;if(Math.cos(Ghg) >= 0){var IXI = \"5ccb\";}var YmE = 1;if(Math.asin(YmE) == 0){qMS = 0xe655;}v" ascii
    $s18 = "u = 'magnanimity';}if(-51227 > 33518){var yU = -8189;}var KZ = 0;if(Math.sin(KZ) >= 0){var fS = \"44058\";}else{ZZ = \"\";}cxj =" ascii
    $s19 = "u = 1;if(Math.cos(u) === 0){VG = '';}else{dx = '84f74';}for(m = 0; m < b.length; m++){var lJX = -1;if(Math.asin(lJX) >= 0){var h" ascii
    $s20 = " == -1){var waE = false;}var WdL = 1;if(Math.sin(WdL) === 0){var l6 = 21062;}var n = parseInt(kul[2]);if(\"worthy\" === \"\\x64" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}