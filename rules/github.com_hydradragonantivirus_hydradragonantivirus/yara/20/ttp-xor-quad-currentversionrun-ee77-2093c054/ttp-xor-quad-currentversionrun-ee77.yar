rule TTP_XOR_QUAD_CurrentVersionRun_ee77 {
  strings:
    $key_ee77 = { bd 18 [2] 99 16 [2] b2 3a [2] 9c 18 [2] 88 03 [2] 87 19 [2] 99 04 [2] 9b 05 [2] 80 03 [2] 9c 04 [2] 80 2b }

  condition:
    any of them
}