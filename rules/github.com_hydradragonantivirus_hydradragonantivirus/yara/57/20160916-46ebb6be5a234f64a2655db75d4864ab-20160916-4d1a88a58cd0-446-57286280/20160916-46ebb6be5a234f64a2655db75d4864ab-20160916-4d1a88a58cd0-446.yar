rule _20160916_46ebb6be5a234f64a2655db75d4864ab_20160916_4d1a88a58cd0_446 {
  meta:
    description = "datamaliciousorder - from files 20160916_46ebb6be5a234f64a2655db75d4864ab.js, 20160916_4d1a88a58cd0419fd28bec2d6cf1068f.js, 20160916_54f6a9ce09bc322c710f889d5f90e29f.js, 20160916_6d6457730c894609ef0b271880778e69.js, 20160916_7a0435ec9d4ae562afef326ee7ad9828.js, 20160916_c6053ff5ba36db965462a2794254119a.js, 20160916_e442065131d3156fae9938b60b94334d.js, 20160916_e52210a1ec8a520c9c5bb50e7fccc631.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e3b14b8ba5dec7cfef89344b6f34a681a952c0d68dbfd464f015843775558e3"
    hash2       = "2f4437b9fe3d7f0f35405535627f9b4954d99c0631f4a3266f6f328d50ab9c69"
    hash3       = "19bb6e0c02d8f77058e9af7062b66271ec489bc083cba04ae21537ed189fdc4e"
    hash4       = "dd6aa734e9da2175a9bc840f55505e9bab36fdea169515be97d7aa84297a017a"
    hash5       = "cd0de4160854ae61a1320a5c73e1a5cdbbefe66297b007de0e16c8481a419f67"
    hash6       = "986227b3ce381b705c1d492088ff69045c3ac5fa43572ea2bf409653a50f55e0"
    hash7       = "b08b9a6a5df777138a7b78bdd418893759a8dccab7ce5bb59ee0de97605039d1"
    hash8       = "f79ccc5925a4e85333370fd004daacb765576be2389f240185b9463e7fed46f5"

  strings:
    $s1 = "\";})()], \"Aq\": [3, (function f(){return \"\\x29\";})()], \"BWb\": [3, (function f(){return \"\\x4d\";})()], \"Yi\": [3, (func" ascii
    $s2 = "\"DAa\": [3, (function f(){return \"0\";})()], \"Ee\": [3, (function f(){return \"4\";})()], \"KJq\": [3, (function f(){return " ascii
    $s3 = ")()], \"Fy\": [3, (function f(){return \"\\x46\";})()], \"Xk\": [3, (function f(){return \"\\x47\";})()], \"HBp\": [3, (function" ascii
    $s4 = "Kx\": [3, (function f(){return \"\\x51\";})()], \"NIj\": [3, (function f(){return \"\\x50\";})()], \"Pg\": [3, (function f(){ret" ascii
    $s5 = "ion f(){return \"\\x57\";})()], \"Ad\": [3, (function f(){return \"\\x56\";})()], \"Mg\": [3, (function f(){return \"\\x55\";})(" ascii
    $s6 = "\"\\x40\";})()], \"VXh\": [3, (function f(){return \"\\x41\";})()], \"Ht\": [3, (function f(){return \"\\x42\";})()], \"Kp\": [3" ascii
    $s7 = "{return \"\\x43\";})()], \"Ne\": [3, (function f(){return \"\\x48\";})()], \"Pc\": [3, (function f(){return \"\\x49\";})()], \"W" ascii
    $s8 = "var WZf = {\"FMt\": [3, (function f(){return \"\\x6b\";})()], \"CVy\": [3, (function f(){return \"\\x79\";})()], \"Ci\": [3, (fu" ascii

  condition:
    (uint16(0) == 0x0a0a and (all of them)
    ) or (all of them)
}