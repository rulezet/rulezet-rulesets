rule _20160921_d1c97b87a6985071e0e4edfb0e0dcc81_20160921_d74d6a32efd0_4065 {
  meta:
    description = "datamaliciousorder - from files 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = ",(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){" ascii
    $s2 = "eturn \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sv\";})()," ascii
    $s3 = "f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TR" ascii
    $s4 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"KDh\";})(),(function f000(" ascii
    $s5 = ")(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000()" ascii
    $s6 = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}