rule TTP_XOR_QUAD_CurrentVersionRun_ee45 {
  strings:
    $key_ee45 = { bd 2a [2] 99 24 [2] b2 08 [2] 9c 2a [2] 88 31 [2] 87 2b [2] 99 36 [2] 9b 37 [2] 80 31 [2] 9c 36 [2] 80 19 }

  condition:
    any of them
}