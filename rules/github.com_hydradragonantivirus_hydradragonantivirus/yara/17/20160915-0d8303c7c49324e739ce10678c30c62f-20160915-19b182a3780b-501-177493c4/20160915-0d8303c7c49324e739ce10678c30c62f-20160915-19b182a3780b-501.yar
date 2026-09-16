rule _20160915_0d8303c7c49324e739ce10678c30c62f_20160915_19b182a3780b_501 {
  meta:
    description = "datamaliciousorder - from files 20160915_0d8303c7c49324e739ce10678c30c62f.js, 20160915_19b182a3780bec9be58145185e5af6d3.js, 20160915_2a2e9ce1c160f138094758a35016b383.js, 20160915_324b53b4c8f0b40bfe1f4aa30cd0e64d.js, 20160915_44a96f894bbda55d8042850146f659f3.js, 20160915_53fe73039a6954d4ad36bb5aa049f8e2.js, 20160915_569b030dc17cda44e02ce0d90647e4cd.js, 20160915_5d2bb55f0980eef17eef866060e477c7.js, 20160915_67421216f169822b12a6e4feee920b98.js, 20160915_7843b344286ce249cf16b29c05a57524.js, 20160915_79c1c66e4d063f11ce2394ac960cb06f.js, 20160915_8b6d3fdebb1c574d1ce4d4f5928c45c0.js, 20160915_8faac99cc8b3d92c318268581d687032.js, 20160915_914cb7f178ab98bb0c47cc07a2f75acc.js, 20160915_9699f23feb4ed3cd90438f6ee2998f2b.js, 20160915_ac78b7b8a99025e418ff72e795e8a829.js, 20160915_b1e9350b98f42c4a63b32be338f408fa.js, 20160915_bcfc721efd9e2ca0092597dd6f6c0523.js, 20160915_cff654b6049f048b78aa16059fe15f72.js, 20160915_e67ac40bc065d44a39c0d5d3a6a1ff70.js, 20160915_e86af221754b855e859d690c6cf0a918.js, 20160915_ec38e32053f4de459fed853cd23742c7.js, 20160915_ec76829958ba2a9c7d1b91c9c94a3702.js, 20160915_f3996c0c0701b4b1b0862ee5cc69baeb.js, 20160915_f39c6deb8e086f464741fc1d83b809a1.js, 20160915_fc88dffc4371541dc85e90832b5212d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88c2fe0daeb167fde4d640c157e79cafea30084f9f88f95b9556fc614ed213d1"
    hash2       = "f35974eb28d2e0c7ab12a2d709d74c406fb2f5821efab16823138ed6200c2132"
    hash3       = "ad0c48c29279db59dddc123f803496b3bba6010c07a802e24150053703fc5ef0"
    hash4       = "129369f3de5abc249eb39866236a3d5f55e98c8e0e6c91035d7a209af060931a"
    hash5       = "0a7d37c0da61a44ec67eda01fbad1876f35be5e2a9fbca9ca626634fa8e9c2e9"
    hash6       = "ec4fded324059a9f109e7953c3dec855405c5adb79e4694e9512bba31fb65a4e"
    hash7       = "2ec6a4a0d58f2069f7bd551e1b606a54bd84c7bed83ae297b58885ad40bd7a02"
    hash8       = "29fd0464174b1164916c909d1a0527a40de2c28e792d52334c1a9d5dc3028f6c"
    hash9       = "9de4e10f689cd59fb81b41296048258b7c7840505ec1c73278ff37399213cb76"
    hash10      = "e49dd139d0f36c4c5866ea3b6554beb0de415143bc8ec78c8577cfc1483c722c"
    hash11      = "76e160c371daa0ccf2cc8da55325c3e84f5d8dcce4a4789fe2c8dfc39bbbab1f"
    hash12      = "e411f399bde3d5b681053d1f74ea1ceee420ba2ef59696298672cb11822b523d"
    hash13      = "b6bd84bc537cb5e63db056024f2f70744d4f00891260768222285a620dfaf72f"
    hash14      = "4e67d213b23e94680d1ee9c1872e3d416e8811e2649fa636cfc1366570b56a54"
    hash15      = "b6f0f9d29c0b51b962b96fa7389a2e9e98a0895f342cbb430c5dc524cd6edce0"
    hash16      = "3a2723fe9621365d1d06fa5fa0b3e65a8e0a6b5129216944f81ee2a06e4b0d4d"
    hash17      = "650b1a970f7423165524712a315bbfd5e9a61cc2827db135d5d23f48d9e02999"
    hash18      = "9ece22ca2996384a286bb9391d1fd932cb14512cb76d9dd6d22369ec296839a6"
    hash19      = "f697c1f71c002f299522338e520879f308cfdfac090a48221d81c684e18139d6"
    hash20      = "e4c4f1830cf603dc844a9b6c38c6b81d65055936a0013befdb4a66c41f34e672"
    hash21      = "b534146f53946d80262e35f0835068577375a44293e961b2bab9e26ce8791a71"
    hash22      = "0491707746d1804870e01b7c56c05de8bc8e4970bfff9dd814494e80d2eb1ba9"
    hash23      = "a05271c2c3216876a7be2063ec0ea2ff2008982e754ff97cea97044eef8f5785"
    hash24      = "2035aef86339d51777bdfab83cf91beb876b02bd85103e2194ed52f343eb7afe"
    hash25      = "dfc0032c2bcd86a67be315e07a75cde09e1aa661f5eaf995f0460ca9425484fb"
    hash26      = "968dd9431047e5d56e193f47e15cdb4cf163f939b479d993a37bdef87ffa01a4"

  strings:
    $s1  = ": [3, (function f(){return \"8\";})()], \"Qq0\": [3, (function f(){return \"\\x44\";})()], \"Zy\": [3, (function f(){return \"" ascii
    $s2  = "\";})()], \"Wf\": [3, (function f(){return \"\\x58\";})()], \"DBk\": [3, (function f(){return \"1\";})()], \"Pe\": [3, (function" ascii
    $s3  = "d\";})()], \"EEn\": [3, (function f(){return \"\\x7a\";})()], \"St\": [3, (function f(){return \"\\x7c\";})()], \"Kr\": [3, (fun" ascii
    $s4  = "on f(){return \"\\x77\";})()], \"BNg\": [3, (function f(){return \"\\x76\";})()], \"GXa\": [3, (function f(){return \"\\x71\";})" ascii
    $s5  = " \"PBq\": [3, (function f(){return \"\\x46\";})()], \"VMm\": [3, (function f(){return \"\\x47\";})()], \"PXx\": [3, (function f(" ascii
    $s6  = ", (function f(){return \"7\";})()], \"YBn\": [3, (function f(){return \"\\x25\";})()], \"Sv\": [3, (function f(){return \"\\x22" ascii
    $s7  = "3, (function f(){return \"\\x70\";})()], \"WAw\": [3, (function f(){return \"\\x73\";})()], \"Nn\": [3, (function f(){return \"" ascii
    $s8  = " \"Hn\": [3, (function f(){return \"0\";})()], \"Hr\": [3, (function f(){return \"4\";})()], \"Fa\": [3, (function f(){return \"" ascii
    $s9  = "){return \"\\x6d\";})()], \"KHz\": [3, (function f(){return \"\\x6e\";})()], \"By\": [3, (function f(){return \"9\";})()], \"IPa" ascii
    $s10 = ")()], \"EKn\": [3, (function f(){return \"\\x29\";})()], \"VYh\": [3, (function f(){return \"\\x4d\";})()], \"Vx\": [3, (functio" ascii
    $s11 = "ion f(){return \"\\x57\";})()], \"QQd\": [3, (function f(){return \"\\x56\";})()], \"Vl\": [3, (function f(){return \"\\x55\";})" ascii
    $s12 = "n\": [3, (function f(){return \"\\x20\";})()], \"FDa\": [3, (function f(){return \"\\x21\";})()], \"Bn\": [3, (function f(){retu" ascii
    $s13 = "(function f(){return \"\\x2a\";})()], \"GVx\": [3, (function f(){return \"5\";})()], \"Nl\": [3, (function f(){return \"3\";})()" ascii
    $s14 = "turn \"\\x4a\";})()], \"Dn\": [3, (function f(){return \"\\x4b\";})()], \"NXi\": [3, (function f(){return \"\\x4c\";})()], \"Cz" ascii
    $s15 = "eturn \"\\x43\";})()], \"Wg\": [3, (function f(){return \"\\x48\";})()], \"IVs\": [3, (function f(){return \"\\x49\";})()], \"CE" ascii
    $s16 = "\"LFv\": [3, (function f(){return \"\\x51\";})()], \"Jp0\": [3, (function f(){return \"\\x50\";})()], \"Qq\": [3, (function f(){" ascii
    $s17 = "40\";})()], \"Ao\": [3, (function f(){return \"\\x41\";})()], \"WLj\": [3, (function f(){return \"\\x42\";})()], \"SHk\": [3, (f" ascii
    $s18 = "3, (function f(){return \"\\x54\";})()], \"Pw\": [3, (function f(){return \"\\x53\";})()], \"Cd\": [3, (function f(){return \"" ascii
    $s19 = "turn \"\\x78\";})()], \"Tb\": [3, (function f(){return \"\\x75\";})()], \"PBp\": [3, (function f(){return \"\\x74\";})()], \"Nc0" ascii
    $s20 = " f(){return \"\\x2e\";})()], \"XLc\": [3, (function f(){return \"\\x2b\";})()], \"MLz\": [3, (function f(){return \"\\x2c\";})()" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}