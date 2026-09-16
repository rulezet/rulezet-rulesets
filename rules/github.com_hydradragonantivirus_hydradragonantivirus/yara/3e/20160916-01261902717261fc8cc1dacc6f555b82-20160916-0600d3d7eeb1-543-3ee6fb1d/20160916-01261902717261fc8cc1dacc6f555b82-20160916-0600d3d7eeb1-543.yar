rule _20160916_01261902717261fc8cc1dacc6f555b82_20160916_0600d3d7eeb1_543 {
  meta:
    description = "datamaliciousorder - from files 20160916_01261902717261fc8cc1dacc6f555b82.js, 20160916_0600d3d7eeb1a72ff5ed81c9f3189d09.js, 20160916_10779f55531b42ff89eda4ac6d131e0b.js, 20160916_1edcd975d242240446166e3a41eb1c06.js, 20160916_2912735dd48c6a320840e841ae48510a.js, 20160916_3228d8ecb4b0fa7802d1f0f9e9ec31a5.js, 20160916_3b99947ae6a9b564138398c579b45dd1.js, 20160916_5734627f4389120a172fa23e2fe5ae56.js, 20160916_6277b1879587d547f2cce10382e5a139.js, 20160916_738efb218b2ed09d7351a29fb59dcf36.js, 20160916_8bdf4c7828eace5c7c8ca0f6e3ad6207.js, 20160916_8e38fbc6f05890213402fbde211d45c9.js, 20160916_bd63e452b36fbc621c0ecfcf8feea0cf.js, 20160916_d44420ba73802fa3444ffb29fb45034c.js, 20160916_e1ab3f0720b6ec56d2bc7371282fa22c.js, 20160916_f7a56d9abd423bfb77f0216be556c0ed.js, 20160916_ff908dc0454bf67ae0a93e59226d8694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c970f49c0974ca1c4ebb5fd83fcaf03ea2bf6290da5ad9c6e82598a05750a13"
    hash2       = "20d52d0ffdf7e852db56a5690c3230b251daa1eafc112763d589d10c89fbd06d"
    hash3       = "82e79805cbe3871780cef226883be0d8b720236fb46bbf02ef6d7e250c953f88"
    hash4       = "85f35767ac895cd515077f27ab1d9fcc9bb223c343a1a75bb71efc16ef2f6a95"
    hash5       = "d2a34240e35aa445f93bf8c0ee21b2c9a6f36ea63a52d9f1484533e3bb8889f0"
    hash6       = "1329dc25938f40eb98356779d792bb716ccc5b5a6c87779274c1135c430b57ce"
    hash7       = "4f5d2a4cc244e47534c461ede6efc362d4bf0a6a91dfa84aed12233cb4297290"
    hash8       = "c1939bfee54ff3a839a7c03ff4e7523e2ed275f343963b503e00baf8738e0e3d"
    hash9       = "a7005fa327837a918c5cabedd925958619d3afa8e086da6b11e11dcd4f02395f"
    hash10      = "d0820951318eb0358d0b569b542cab296c4d34d25e34e85390a9627db52b3737"
    hash11      = "9d15fe6d5d5f84715ea39de954b8cc038bcfd206686d916665a9276fa1551c09"
    hash12      = "210c55a62c367e0b0930e5790eec58677c0edac4c679d62feea2e3c09ee037be"
    hash13      = "e1a7eb6cb75b7123ffc06ef8ad70d89c36797177f9bf50d63df419c07a0eb5fe"
    hash14      = "a1344c580b34c5ff42e4b1a2b6c03c8dd5c32e7f5aaadcd163567247202c4091"
    hash15      = "47596115d296026b48756ba1cad2e893d525f743c532fd96b8602d279a52e2c8"
    hash16      = "c56a3a0eb4344eb058dc2f569c2ca6d0f9d63c7f3bd024594aba919051a7a605"
    hash17      = "c05f9f5131a5eac8ecc6af0e027a546214162d539e79b7e9ab15cc2f7e906ea0"

  strings:
    $s1  = "\\x40\";})()], \"IPx\": [3, (function f(){return \"\\x41\";})()], \"Ee\": [3, (function f(){return \"\\x42\";})()], \"Kp\": [3, " ascii
    $s2  = "rn \"\\x4e\";})()], \"Ks\": [3, (function f(){return \"\\x4f\";})()], \"Ze\": [3, (function f(){return \"2\";})()], \"Ut\": [3, " ascii
    $s3  = "return \"\\x43\";})()], \"Fy\": [3, (function f(){return \"\\x48\";})()], \"VXh\": [3, (function f(){return \"\\x49\";})()], \"W" ascii
    $s4  = ")()], \"Gd\": [3, (function f(){return \"\\x58\";})()], \"Kw0\": [3, (function f(){return \"1\";})()], \"XAu\": [3, (function f(" ascii
    $s5  = "\";})()], \"Aq\": [3, (function f(){return \"\\x29\";})()], \"BWb\": [3, (function f(){return \"\\x4d\";})()], \"Xk\": [3, (func" ascii
    $s6  = "()], \"Ne\": [3, (function f(){return \"\\x46\";})()], \"Yi\": [3, (function f(){return \"\\x47\";})()], \"HBp\": [3, (function " ascii
    $s7  = "on f(){return \"\\x77\";})()], \"LUb\": [3, (function f(){return \"\\x76\";})()], \"WCx\": [3, (function f(){return \"\\x71\";})" ascii
    $s8  = "ction f(){return \"\\x2e\";})()], \"Fg\": [3, (function f(){return \"\\x2b\";})()], \"Cv\": [3, (function f(){return \"\\x2c\";}" ascii
    $s9  = "var WZf = {\"Om\": [3, (function f(){return \"\\x6b\";})()], \"CVy\": [3, (function f(){return \"\\x79\";})()], \"Ci\": [3, (fun" ascii
    $s10 = "Kx\": [3, (function f(){return \"\\x51\";})()], \"Vr\": [3, (function f(){return \"\\x50\";})()], \"Pg\": [3, (function f(){retu" ascii
    $s11 = "\"\\x7d\";})()], \"Ht\": [3, (function f(){return \"\\x7a\";})()], \"Pw\": [3, (function f(){return \"\\x7c\";})()], \"VXz\": [3" ascii
    $s12 = "{return \"\\x7b\";})()], \"Pq\": [3, (function f(){return \"\\x2f\";})()], \"HIs\": [3, (function f(){return \"\\x2d\";})()], \"" ascii
    $s13 = "ion f(){return \"\\x57\";})()], \"Pc\": [3, (function f(){return \"\\x56\";})()], \"Mg\": [3, (function f(){return \"\\x55\";})(" ascii
    $s14 = ")], \"ZLu\": [3, (function f(){return \"\\x0d\";})()], \"JDt\": [3, (function f(){return \"\\x09\";})()], \"DYm\": [3, (function" ascii
    $s15 = "turn \"\\x78\";})()], \"GEb\": [3, (function f(){return \"\\x75\";})()], \"Wx\": [3, (function f(){return \"\\x74\";})()], \"PCp" ascii
    $s16 = "\"DAa\": [3, (function f(){return \"0\";})()], \"GQo\": [3, (function f(){return \"4\";})()], \"KJq\": [3, (function f(){return " ascii
    $s17 = "Pd\": [3, (function f(){return \"8\";})()], \"NIj\": [3, (function f(){return \"\\x44\";})()], \"XUi\": [3, (function f(){return" ascii
    $s18 = "return \"\\x4a\";})()], \"Fw\": [3, (function f(){return \"\\x4b\";})()], \"Ad\": [3, (function f(){return \"\\x4c\";})()], \"UT" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}