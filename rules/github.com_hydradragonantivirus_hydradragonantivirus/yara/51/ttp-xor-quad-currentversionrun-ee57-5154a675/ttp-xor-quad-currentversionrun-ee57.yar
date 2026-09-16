rule TTP_XOR_QUAD_CurrentVersionRun_ee57 {
  strings:
    $key_ee57 = { bd 38 [2] 99 36 [2] b2 1a [2] 9c 38 [2] 88 23 [2] 87 39 [2] 99 24 [2] 9b 25 [2] 80 23 [2] 9c 24 [2] 80 0b }

  condition:
    any of them
}