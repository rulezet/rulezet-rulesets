rule TTP_XOR_QUAD_CurrentVersionRun_ee37 {
  strings:
    $key_ee37 = { bd 58 [2] 99 56 [2] b2 7a [2] 9c 58 [2] 88 43 [2] 87 59 [2] 99 44 [2] 9b 45 [2] 80 43 [2] 9c 44 [2] 80 6b }

  condition:
    any of them
}