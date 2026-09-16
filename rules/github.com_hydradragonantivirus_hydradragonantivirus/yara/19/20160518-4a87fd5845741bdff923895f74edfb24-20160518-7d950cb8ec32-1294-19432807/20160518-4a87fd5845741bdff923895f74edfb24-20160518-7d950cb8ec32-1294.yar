rule _20160518_4a87fd5845741bdff923895f74edfb24_20160518_7d950cb8ec32_1294 {
  meta:
    description = "datamaliciousorder - from files 20160518_4a87fd5845741bdff923895f74edfb24.js, 20160518_7d950cb8ec32d1e7d485815869506a04.js, 20160518_ca01cf9481c3335f56c7ddc9e810a425.js, 20160518_cece7f7ef0ed031e33894a91134cd6d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c89c2711c75cbdd296b3bc2e02e6e3f5aae24d51abd031c57e24620e84fc1eb"
    hash2       = "b2775c3e1146b2589a2454a5605dc8c42d55561ee96479e83a79438d0605593d"
    hash3       = "aad8a3bbd6a184a8b7af492ed3bd4965e76b4b6658ef60b74201592f670a9983"
    hash4       = "f1eef3679c71788de7c2cb6a5a02422d99a11af104bf827793acbccbe77492a6"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* z  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* z  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* z  */, A8name /* z  *" ascii
    $s4 = "dot1 /* z  */= true;/* z  */" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* z  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}