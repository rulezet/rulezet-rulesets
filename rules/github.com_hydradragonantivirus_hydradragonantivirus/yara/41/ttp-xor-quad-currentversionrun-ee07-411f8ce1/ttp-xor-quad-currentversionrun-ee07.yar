rule TTP_XOR_QUAD_CurrentVersionRun_ee07 {
  strings:
    $key_ee07 = { bd 68 [2] 99 66 [2] b2 4a [2] 9c 68 [2] 88 73 [2] 87 69 [2] 99 74 [2] 9b 75 [2] 80 73 [2] 9c 74 [2] 80 5b }

  condition:
    any of them
}