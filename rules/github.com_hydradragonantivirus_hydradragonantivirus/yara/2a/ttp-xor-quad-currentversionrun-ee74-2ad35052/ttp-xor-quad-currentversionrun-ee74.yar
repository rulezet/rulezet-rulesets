rule TTP_XOR_QUAD_CurrentVersionRun_ee74 {
  strings:
    $key_ee74 = { bd 1b [2] 99 15 [2] b2 39 [2] 9c 1b [2] 88 00 [2] 87 1a [2] 99 07 [2] 9b 06 [2] 80 00 [2] 9c 07 [2] 80 28 }

  condition:
    any of them
}