rule TTP_XOR_QUAD_CurrentVersionRun_1317 {
  strings:
    $key_1317 = { 40 78 [2] 64 76 [2] 4f 5a [2] 61 78 [2] 75 63 [2] 7a 79 [2] 64 64 [2] 66 65 [2] 7d 63 [2] 61 64 [2] 7d 4b }

  condition:
    any of them
}