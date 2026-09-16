rule TTP_XOR_QUAD_CurrentVersionRun_4b17 {
  strings:
    $key_4b17 = { 18 78 [2] 3c 76 [2] 17 5a [2] 39 78 [2] 2d 63 [2] 22 79 [2] 3c 64 [2] 3e 65 [2] 25 63 [2] 39 64 [2] 25 4b }

  condition:
    any of them
}