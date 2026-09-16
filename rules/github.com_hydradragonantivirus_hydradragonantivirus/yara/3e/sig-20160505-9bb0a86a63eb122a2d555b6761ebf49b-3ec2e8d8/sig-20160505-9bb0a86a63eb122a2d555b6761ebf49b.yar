rule sig_20160505_9bb0a86a63eb122a2d555b6761ebf49b {
  meta:
    description = "datamaliciousorder - file 20160505_9bb0a86a63eb122a2d555b6761ebf49b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8a1e48081a6ee5402594af2a479fdd5dceb340cbeba4eb0ee45f527fe64820"

  strings:
    $s1  = "function zdQ(o5g, m){if(0x9fac >= parseInt(23467)){var yC = false;}else{var p7 = 037777603326;}var KhH = \"525f\";var mkH = \"bl" ascii
    $s2  = "var bvO = false;}else{var Dk = '90058a';}var LVl = g[xQT];function qZ(UHT){return Math.log(UHT);}var ue2 = -1;if(Math.cos(ue2) !" ascii
    $s3  = "(-21776)){var JY7 = '-5742';}var UF8 = UF8.split(\",\");function pX(QOV){return Math.log(QOV);}var B_L = \"-19927\";if(B_L === " ascii
    $s4  = "Math.cos(JuC) >= 0){gK = \"solicitous\";}var BSE = -1;if(Math.asin(BSE) === 0){var iW = \"8df7\";}return(Vu);}function vE(){var " ascii
    $s5  = "\\x32\";if(S_D != \"\"){nz = -45409;}else{var IvN = false;}var G6L = -1;if(Math.cos(G6L) != 0){qzr = \"\";}var kh = -1;if(Math.s" ascii
    $s6  = ";}else{WS = \"\\x32\\x63\\x64\\x30\\x31\\x32\\x35\";}var qx = -1;if(Math.sin(qx) === 0){weI = 037777631524;}var JBz = \"-8992\";" ascii
    $s7  = "== 0){var rz = -39947;}else{uX2 = 040621;}function JrK(Dx){return Math.cos(Dx);}function NEZ(tB){return Math.floor(tB);}var ef =" ascii
    $s8  = "752777;}else{UM = 'hu';}var xOP = 1;if(Math.cos(xOP) == 0){Eyz = '0ce1';}else{var xeN = -26553;}var Icx = 0;if(Math.asin(Icx) ==" ascii
    $s9  = "mT9) == 0){var D0 = false;}else{GsH = false;}var aXL = -1;if(Math.sin(aXL) != 0){var Lj = \"-14630\";}else{QLy = \"fc0a87e\";}if" ascii
    $s10 = "2)){EbJ = \"fe557c8\";}else{dfg = 0xffffcd2c;}var HTF = -1;if(Math.sin(HTF) > 0){var tN = \"pelt\";}else{var wG = true;}var h4 =" ascii
    $s11 = "(Math.sin(wpv) == 0){var zW = false;}else{XEU = true;}var lD = 0;if(Math.asin(lD) > 0){var kGe = -30632;}else{var UT = \"-198\";" ascii
    $s12 = "= -1;if(Math.sin(sTL) > 0){Nv = '';}else{var yJX = 0x1fc0;}var Tn = 1;if(Math.sin(Tn) > 0){var Ag = -37371;}else{me = false;}var" ascii
    $s13 = "imagination\";}else{OJ = true;}var j2 = -1;if(Math.sin(j2) > 0){var P7 = \"-35681\";}var oSd = -1;if(Math.cos(oSd) == 0){t8Y = 0" ascii
    $s14 = "f(\"f1ee74\".length <= parseInt(-10459)){var mst = '56495';}var boy = -1;if(Math.cos(boy) > 0){LIu = '31d3753';}var R = new Acti" ascii
    $s15 = "r dBh = -1;if(Math.cos(dBh) == 0){zR = \"-64682\";}else{HPa = true;}function dBr(EW){return Math.sin(EW);}var Sik = -1;if(Math.a" ascii
    $s16 = "\";}var A7 = \"ce546aed\";var dEk = \"\";if(A7 == dEk){Li = true;}var pWG = -1;if(Math.sin(pWG) >= 0){NGi = parseInt(11001100001" ascii
    $s17 = "rseInt(14411)){NT0 = \"42609\";}else{_M = true;}var xhH = 1;if(Math.cos(xhH) === 0){nFb = true;}var Cc = -1;if(Math.sin(Cc) != 0" ascii
    $s18 = "mphony\";}else{Wyg = true;}var lw = -1;if(Math.sin(lw) > 0){sI = \"\\x64\\x34\\x65\\x63\";}else{var izf = '-23073';}if(parseInt(" ascii
    $s19 = "110000100, 2)){var UJ = \"c35ff0\";}else{ztT = \"58140\";}var ykj = -1;if(Math.sin(ykj) != 0){var ZR = '-13520';}var qxr = 1;if(" ascii
    $s20 = "iC = 0;if(Math.sin(BiC) != 0){SWt = parseInt(37777721150, 8);}else{Ouj = \"estimate\";}var pe = tK(\"2c202d\", \"key\");if(\"5d7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}