rule TTP_XOR_QUAD_CurrentVersionRun_ee66 {
  strings:
    $key_ee66 = { bd 09 [2] 99 07 [2] b2 2b [2] 9c 09 [2] 88 12 [2] 87 08 [2] 99 15 [2] 9b 14 [2] 80 12 [2] 9c 15 [2] 80 3a }

  condition:
    any of them
}