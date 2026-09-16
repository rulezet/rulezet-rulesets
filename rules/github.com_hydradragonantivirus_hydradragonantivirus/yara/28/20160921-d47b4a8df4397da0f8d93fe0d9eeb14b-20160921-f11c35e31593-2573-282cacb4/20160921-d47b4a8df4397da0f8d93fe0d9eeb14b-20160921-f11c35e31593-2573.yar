rule _20160921_d47b4a8df4397da0f8d93fe0d9eeb14b_20160921_f11c35e31593_2573 {
  meta:
    description = "datamaliciousorder - from files 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s2 = "tion f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return" ascii
    $s3 = "Xg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "on f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s7 = "turn \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8 = "000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}