rule _20160915_031b2b2a81760f73383b635c23771175_20160915_0bcc48d7fb02_982 {
  meta:
    description = "datamaliciousorder - from files 20160915_031b2b2a81760f73383b635c23771175.js, 20160915_0bcc48d7fb02efaa1bab6e89b146f764.js, 20160915_3138739031b0a3053454b4b54fa31d03.js, 20160915_4c4e6c5e00e3fbb2db1ba4cea397d7e0.js, 20160915_559168ed0abccd0006b29eebf90846e9.js, 20160915_679b639909db09724ceca828b50ef7c9.js, 20160915_69630d6e9a244df7b54992f16f58ddbb.js, 20160915_69e69240c0457ca9e319e312de0d9424.js, 20160915_7e973ac6b0539ffc8c93565b1843bd55.js, 20160915_7f10bbf26df5e52edd57ae0f085cec55.js, 20160915_93ef39077c6e7ab43365d3b16cbfd471.js, 20160915_99f4f15923c00f81bf562e27722726d5.js, 20160915_a05b912e01b446bf7cef2f2ad9b145cf.js, 20160915_c2afafc149146ec3fe4b2f77630e5b8b.js, 20160915_e473b954e609eadc4b3a7ca7003e0daa.js, 20160915_efc366d01cc06469e3afc0cd4d772372.js, 20160915_fe2ec371441931018c1083887b29b5c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15e0385b21c2cd45218a9a5a467c524b8a3ad30f0020fb22f91d64e78e303e3b"
    hash2       = "27789f4af47a3d5e11068052c151dbe80d62e6c90a544a49d79ea47157978225"
    hash3       = "6ec5e6fcb1777af4d0367fd89d5326af3d8cdfdb9490c4c1661eddd17c73e998"
    hash4       = "096eb5863fb070ce3ba1cc9b25371fea21a893ee2c6efe381bce57b708acb7a8"
    hash5       = "d6ec31156daf1f567ed58c7ce44061ce5b669830a06195447ab779a03d438394"
    hash6       = "29861ae54d2d14f7e70aa90cbf8f745a26b7b7787f418ff5dea7695dcbb174e7"
    hash7       = "50f3fc02dbb4c1a6e46f413a3a9e341645a5a1b62a1c2f69a65db5a01d005aa9"
    hash8       = "67b70abd444ad3b0c8aff4ccbc9172c5c9eee59955fa65e9e1641be62ed0fe65"
    hash9       = "83ab6cfdb947f38417b43e792e074a7b53acd62ecb9b2b487f7d5333c8cd34dc"
    hash10      = "27ff1bfb35cdd125d50052c1b5a505486fab787126d36a863cbd513e40b7e5d7"
    hash11      = "d86bac27e77f92c98c1a061066dcb9400d37be98776ebf8a4519df82b4d18472"
    hash12      = "0377cd52c543eec3c8ef6972f9f0fa9f9319e0660065962d7ef922177929b2cd"
    hash13      = "bdd56b075b7b18221e1598e3e5f15d13089c9514a9828825f83d5f87f65c31f6"
    hash14      = "098412e6ccf57525812cb9432c7f90df5255e6b1e314208cb1592f54b41d7dd4"
    hash15      = "77e084cb9b3918c049ff58e117ef3d0e18c65c27a0e7d73efb9d43b358560382"
    hash16      = "50a99e8196d2850617ad0c7bbba880435a128e50db3a06f020b426770a1db73c"
    hash17      = "ee84ae599a810ad3f82d6160d8fcc5fa2bb3a2062006785490adefd51bf86045"

  strings:
    $s1  = "\\x4e\";})()], \"Jp\": [3, (function f(){return \"\\x4f\";})()], \"Ha\": [3, (function f(){return \"2\";})()], \"MLz\": [3, (fun" ascii
    $s2  = "n \"\\x7b\";})()], \"Sc\": [3, (function f(){return \"\\x2f\";})()], \"CKa\": [3, (function f(){return \"\\x2d\";})()], \"Ql\": " ascii
    $s3  = "], \"EKn\": [3, (function f(){return \"\\x29\";})()], \"VYh\": [3, (function f(){return \"\\x4d\";})()], \"VMm\": [3, (function " ascii
    $s4  = "\"Dn\": [3, (function f(){return \"0\";})()], \"Of\": [3, (function f(){return \"4\";})()], \"Fa\": [3, (function f(){return \"" ascii
    $s5  = "[3, (function f(){return \"8\";})()], \"QQd\": [3, (function f(){return \"\\x44\";})()], \"Zy\": [3, (function f(){return \"\\x4" ascii
    $s6  = "nction f(){return \"\\x2a\";})()], \"GVx\": [3, (function f(){return \"5\";})()], \"Nl\": [3, (function f(){return \"3\";})()], " ascii
    $s7  = "\";})()], \"Hn\": [3, (function f(){return \"\\x7a\";})()], \"St\": [3, (function f(){return \"\\x7c\";})()], \"Kr\": [3, (funct" ascii
    $s8  = "function f(){return \"7\";})()], \"YBn\": [3, (function f(){return \"\\x25\";})()], \"Sv\": [3, (function f(){return \"\\x22\";}" ascii
    $s9  = "(){return \"\\x2e\";})()], \"XLc\": [3, (function f(){return \"\\x2b\";})()], \"Wg\": [3, (function f(){return \"\\x2c\";})()], " ascii
    $s10 = ";})()], \"GXa\": [3, (function f(){return \"\\x41\";})()], \"EEn\": [3, (function f(){return \"\\x42\";})()], \"SHk\": [3, (func" ascii
    $s11 = " [3, (function f(){return \"\\x20\";})()], \"FDa\": [3, (function f(){return \"\\x21\";})()], \"Bn\": [3, (function f(){return " ascii
    $s12 = "var COt = {\"MGt\": [3, (function f(){return \"\\x6b\";})()], \"FTe\": [3, (function f(){return \"\\x79\";})()], \"Hh\": [3, (fu" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}