rule TTP_XOR_QUAD_CurrentVersionRun_ee68 {
  strings:
    $key_ee68 = { bd 07 [2] 99 09 [2] b2 25 [2] 9c 07 [2] 88 1c [2] 87 06 [2] 99 1b [2] 9b 1a [2] 80 1c [2] 9c 1b [2] 80 34 }

  condition:
    any of them
}