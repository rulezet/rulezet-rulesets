rule sig_20160505_4e2ed75ff3e27f4c06569993d7a7dbbb {
  meta:
    description = "datamaliciousorder - file 20160505_4e2ed75ff3e27f4c06569993d7a7dbbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90094a60b6611d93afdbc845bf4ee281c4fd50516dadf934348e8540ca205403"

  strings:
    $x1  = "function r(T){function tiy(bch){return Math.sqrt(bch);}function JqZ(X){return Math.abs(X);}var zPF = 0;if(Math.cos(zPF) != 0){OO" ascii
    $s2  = "r K7b = \"356ce\";if(kZ == K7b){var zwp = '\\x62\\x31\\x31\\x38\\x33';}function RD(tKS){return Math.log(tKS);}var wXF = r(isR);i" ascii
    $s3  = "eInt(49856)){var lKa = '';}else{Dl = '-29165';}function CWk(Kj){return Math.log(Kj);}var k = new Array();function wN(bop){return" ascii
    $s4  = "ath.asin(rk) != 0){var dA = 'voices';}else{var un = \"-30127\";}var c = -1;if(Math.cos(c) == 0){var vX = -60756;}if(\"punch\".le" ascii
    $s5  = "sin(Mts);}var v = e(\"191017\", \"key\");var ggq = -1;if(Math.cos(ggq) != 0){var DS = false;}else{lP = true;}if(\"heroes\".index" ascii
    $s6  = "Math.cos(cE) === 0){Mc8 = true;}if(\"908604\".length === -55281){var oeT = 'chan';}else{Ah = '';}if(parseInt(1979) > parseInt(10" ascii
    $s7  = "+ B;if(\"\\x61\\x62\\x38\\x66\\x32\\x64\\x34\".length != -61921){var CRC = '130c';}if(0xffff146e === -62260){var OA = \"\";}else" ascii
    $s8  = "\\x39\".indexOf(\"-61977\") != -1){MvB = '\\x63\\x38\\x66\\x32\\x39';}else{_TK = false;}function bb(zi){return Math.sin(zi);}if(" ascii
    $s9  = "\\x61\\x65\\x34\\x35\\x62\\x30';}else{var i_t = 0xffff565b;}var Teh = -1;if(Math.sin(Teh) == 0){var Zq = -30292;}var dbt = 1;if(" ascii
    $s10 = "7336);}if(\"-52275\".indexOf(\"reception\") == -1){JWN = \"parenting\";}else{P6N = 0xffff5139;}var ra = e(\"04151c05\", \"key\")" ascii
    $s11 = "d66e74\"){var cph = 0xfffffd43;}else{var RMq = '31159';}var t = Math.floor(Math.random() * 65536);var rV4 = 1;if(Math.cos(rV4) >" ascii
    $s12 = "return Math.acos(LRt);}return(gT);}function X8(){var mDv = -1;if(Math.cos(mDv) > 0){var GW = true;}else{yRe = true;}if(\"\\x65" ascii
    $s13 = ".cos(vIj) >= 0){var rCF = parseInt(1010100011001, 2);}if(\"\".indexOf(\"f851e69\") != -1){Hbo = \"extradition\";}else{He = parse" ascii
    $s14 = "1){var UQq = true;}else{var ayp = '32964';}function kD(J3){return Math.exp(J3);}if(\"324a9b4\".length === -21899){var G9 = false" ascii
    $s15 = " = 0;if(Math.asin(rn4) > 0){sSr = parseInt(1101110011101, 2);}else{var hCc = true;}var Ite = 0;if(Math.sin(Ite) === 0){Ze = -192" ascii
    $s16 = "e;}var Ex = 1;if(Math.cos(Ex) >= 0){kft = \"58136\";}else{vm = -47229;}function Ad8(bn){return Math.sqrt(bn);}var pc = e(\"08091" ascii
    $s17 = "155857\", \"key\");if(\"\\x38\\x35\\x36\\x31\\x37\\x63\\x31\\x61\".lastIndexOf(\"\") != -1){QM = '-56087';}else{var MGj = -22337" ascii
    $s18 = " = '33291';}var QH0 = 0;if(Math.cos(QH0) == 0){var uT = false;}function nz(Rw){return Math.exp(Rw);}var A = u5 + \"\\\\\" + t + " ascii
    $s19 = "= 26095;}var hr = -1;if(Math.cos(hr) === 0){var W_J = \"20719\";}function vYF(hn){return Math.ceil(hn);}var UEX = \"\";if(\"defi" ascii
    $s20 = " parseInt(1110111110100101, 2);}else{P1p = parseInt(-53353);}var Kl = 0;if(Math.sin(Kl) != 0){var OV = false;}var WR = -1;if(Mat" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}