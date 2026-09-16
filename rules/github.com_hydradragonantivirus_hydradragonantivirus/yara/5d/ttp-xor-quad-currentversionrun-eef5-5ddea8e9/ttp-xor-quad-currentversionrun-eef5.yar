rule TTP_XOR_QUAD_CurrentVersionRun_eef5 {
  strings:
    $key_eef5 = { bd 9a [2] 99 94 [2] b2 b8 [2] 9c 9a [2] 88 81 [2] 87 9b [2] 99 86 [2] 9b 87 [2] 80 81 [2] 9c 86 [2] 80 a9 }

  condition:
    any of them
}