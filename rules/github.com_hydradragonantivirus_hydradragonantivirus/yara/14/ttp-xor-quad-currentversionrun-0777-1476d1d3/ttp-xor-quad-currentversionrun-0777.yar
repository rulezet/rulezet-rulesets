rule TTP_XOR_QUAD_CurrentVersionRun_0777 {
  strings:
    $key_0777 = { 54 18 [2] 70 16 [2] 5b 3a [2] 75 18 [2] 61 03 [2] 6e 19 [2] 70 04 [2] 72 05 [2] 69 03 [2] 75 04 [2] 69 2b }

  condition:
    any of them
}