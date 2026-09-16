rule TTP_XOR_QUAD_CurrentVersionRun_ee67 {
  strings:
    $key_ee67 = { bd 08 [2] 99 06 [2] b2 2a [2] 9c 08 [2] 88 13 [2] 87 09 [2] 99 14 [2] 9b 15 [2] 80 13 [2] 9c 14 [2] 80 3b }

  condition:
    any of them
}