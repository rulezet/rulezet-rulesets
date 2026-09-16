rule TTP_XOR_QUAD_CurrentVersionRun_ee75 {
  strings:
    $key_ee75 = { bd 1a [2] 99 14 [2] b2 38 [2] 9c 1a [2] 88 01 [2] 87 1b [2] 99 06 [2] 9b 07 [2] 80 01 [2] 9c 06 [2] 80 29 }

  condition:
    any of them
}