rule TTP_XOR_QUAD_CurrentVersionRun_eef8 {
  strings:
    $key_eef8 = { bd 97 [2] 99 99 [2] b2 b5 [2] 9c 97 [2] 88 8c [2] 87 96 [2] 99 8b [2] 9b 8a [2] 80 8c [2] 9c 8b [2] 80 a4 }

  condition:
    any of them
}