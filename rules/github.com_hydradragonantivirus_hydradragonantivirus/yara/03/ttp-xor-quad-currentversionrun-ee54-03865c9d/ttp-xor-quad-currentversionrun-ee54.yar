rule TTP_XOR_QUAD_CurrentVersionRun_ee54 {
  strings:
    $key_ee54 = { bd 3b [2] 99 35 [2] b2 19 [2] 9c 3b [2] 88 20 [2] 87 3a [2] 99 27 [2] 9b 26 [2] 80 20 [2] 9c 27 [2] 80 08 }

  condition:
    any of them
}