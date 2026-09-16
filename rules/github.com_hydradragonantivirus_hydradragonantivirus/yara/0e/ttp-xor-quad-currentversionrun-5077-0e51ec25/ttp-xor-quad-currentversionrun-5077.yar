rule TTP_XOR_QUAD_CurrentVersionRun_5077 {
  strings:
    $key_5077 = { 03 18 [2] 27 16 [2] 0c 3a [2] 22 18 [2] 36 03 [2] 39 19 [2] 27 04 [2] 25 05 [2] 3e 03 [2] 22 04 [2] 3e 2b }

  condition:
    any of them
}