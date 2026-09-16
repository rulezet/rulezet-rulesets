rule TTP_XOR_QUAD_CurrentVersionRun_ee34 {
  strings:
    $key_ee34 = { bd 5b [2] 99 55 [2] b2 79 [2] 9c 5b [2] 88 40 [2] 87 5a [2] 99 47 [2] 9b 46 [2] 80 40 [2] 9c 47 [2] 80 68 }

  condition:
    any of them
}