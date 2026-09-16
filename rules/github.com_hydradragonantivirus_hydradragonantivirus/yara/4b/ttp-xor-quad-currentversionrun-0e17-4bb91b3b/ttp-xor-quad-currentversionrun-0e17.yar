rule TTP_XOR_QUAD_CurrentVersionRun_0e17 {
  strings:
    $key_0e17 = { 5d 78 [2] 79 76 [2] 52 5a [2] 7c 78 [2] 68 63 [2] 67 79 [2] 79 64 [2] 7b 65 [2] 60 63 [2] 7c 64 [2] 60 4b }

  condition:
    any of them
}