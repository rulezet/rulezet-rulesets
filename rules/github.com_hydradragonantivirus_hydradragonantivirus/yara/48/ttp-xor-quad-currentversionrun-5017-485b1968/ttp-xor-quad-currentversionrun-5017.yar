rule TTP_XOR_QUAD_CurrentVersionRun_5017 {
  strings:
    $key_5017 = { 03 78 [2] 27 76 [2] 0c 5a [2] 22 78 [2] 36 63 [2] 39 79 [2] 27 64 [2] 25 65 [2] 3e 63 [2] 22 64 [2] 3e 4b }

  condition:
    any of them
}