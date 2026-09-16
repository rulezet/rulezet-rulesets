rule sig_20160506_27af553011b4c5f2ada291f87bf08956 {
  meta:
    description = "datamaliciousorder - file 20160506_27af553011b4c5f2ada291f87bf08956.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb6f7c5e2a49ea51685122f137637fe02ded61d91bc9ace7e2d1eb3db49d3432"

  strings:
    $x1  = "function G(){var k = \"-23108\";var C = \"\";if(k == C){var Ep = \"c4471e\";}else{Npr = \"\";}if(\"-40852\".indexOf(\"8f0a57c\")" ascii
    $s2  = " ZN = 0;if(Math.cos(ZN) == 0){zQX = true;}function Bz(r3F){return Math.log(r3F);}if(\"-53340\".indexOf(\"-39954\") != -1){iMZ = " ascii
    $s3  = "dexOf(\"58688\") == 0){var mgk = \"-47560\";}else{var wCV = -27990;}if(\"passwords\".lastIndexOf(\"-57603\") == 0){dw = \"\\x61" ascii
    $s4  = "f){return Math.floor(Qf);}var WFQ = wu + \"\\\\\" + RY + \".\" + s;var Lg_ = -1;if(Math.sin(Lg_) >= 0){ns = false;}if(\"\\x39\\x" ascii
    $s5  = "ath.sin(ny) === 0){Ibx = true;}else{cq = '14259';}if(\"\\x61\\x62\\x32\\x33\\x37\\x36\\x62\".indexOf(\"\\x38\\x62\\x30\\x34\") =" ascii
    $s6  = "r RY = Math.floor(Math.random() * 65536);var l = -1;if(Math.acos(l) != 0){cpZ = \"48294\";}else{dhf = 0xffff0603;}if(\"-33602\"." ascii
    $s7  = "f(Math.acos(Rt) != 0){var QWB = '-19771';}VS = VS + 1;var UL = 1;if(Math.asin(UL) == 0){var g6 = false;}var IK = 0;if(Math.sin(I" ascii
    $s8  = ";var sE = 0;if(Math.sin(sE) === 0){way = 0x9d40;}if(parseInt(34521, 8) >= -28355){Wb = true;}else{XRh = -58649;}if(-59396 >= par" ascii
    $s9  = "erlands\";}var rxl = -1;if(Math.cos(rxl) == 0){Ozt = \"\";}else{var t4 = 'gates';}if(-9988 > parseInt(44628)){var xE = 'paths';}" ascii
    $s10 = "r M = \"\";if(iO == M){ia = parseInt(-42100);}else{var Q8 = true;}var P4 = -1;if(Math.sin(P4) != 0){O = false;}if(\"\" == \"-419" ascii
    $s11 = "660\") == -1){NB = 0160462;}if(57786 <= 0xffff930c){VG = '';}var lJX = 1;if(Math.sin(lJX) != 0){IC = false;}else{var Da = \"\";}" ascii
    $s12 = " ri(\"03452f26195f424f035a3f3f011d\", \"n6WKuml7\");function Al(Nc_){return Math.tan(Nc_);}var Hhk = -1;if(Math.acos(Hhk) == 0){" ascii
    $s13 = "}var LF = -1;if(Math.sin(LF) >= 0){var Cid = \"\\x66\\x34\\x37\\x30\\x66\";}else{var X = 0xffff5316;}if(\"4a342b\" != \"\"){var " ascii
    $s14 = " false;}if(parseInt(14885) >= 033274){var Mmu = '57066';}var VN = nvb(YJ);var Zp = -1;if(Math.sin(Zp) == 0){var OeB = 'bf3e0df';" ascii
    $s15 = "05676, 8);}else{var jxm = true;}if(\"42126\".length != 33478){bE6 = '-57988';}else{wMu = false;}var Dh = -1;if(Math.sin(Dh) != 0" ascii
    $s16 = "0){var bP = '\\x66\\x62\\x65\\x35';}else{Hbj = '\\x32\\x61\\x66\\x65\\x30\\x62\\x30\\x32';}var OF = -1;if(Math.sin(OF) != 0){w69" ascii
    $s17 = "f(\"395\".indexOf(\"25460\") == 0){var ToK = 'kissing';}var z0 = -1;if(Math.cos(z0) == 0){var Ud = \"5606\";}else{Fo = \"a0f1720" ascii
    $s18 = "Z4 = 1;if(Math.asin(Z4) >= 0){var jE = '';}var yf = -1;if(Math.sin(yf) != 0){Xx = -10509;}else{var To = true;}if(\"madison\".las" ascii
    $s19 = " = '';}var Vm = -1;if(Math.sin(Vm) > 0){var j2 = '';}else{var mJ = \"bruise\";}var Is = 0;if(Math.sin(Is) === 0){var W_ = true;}" ascii
    $s20 = "\"bequeath\") == -1){var rLN = '';}else{un = '-56282';}function Qzs(ExO){return Math.tan(ExO);}if(\"1d12a2\".length <= -52073){g" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}