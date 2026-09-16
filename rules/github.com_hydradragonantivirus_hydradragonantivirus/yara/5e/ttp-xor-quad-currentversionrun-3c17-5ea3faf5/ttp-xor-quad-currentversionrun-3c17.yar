rule TTP_XOR_QUAD_CurrentVersionRun_3c17 {
  strings:
    $key_3c17 = { 6f 78 [2] 4b 76 [2] 60 5a [2] 4e 78 [2] 5a 63 [2] 55 79 [2] 4b 64 [2] 49 65 [2] 52 63 [2] 4e 64 [2] 52 4b }

  condition:
    any of them
}