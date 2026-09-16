rule TTP_XOR_QUAD_CurrentVersionRun_ee44 {
  strings:
    $key_ee44 = { bd 2b [2] 99 25 [2] b2 09 [2] 9c 2b [2] 88 30 [2] 87 2a [2] 99 37 [2] 9b 36 [2] 80 30 [2] 9c 37 [2] 80 18 }

  condition:
    any of them
}