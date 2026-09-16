rule TTP_XOR_QUAD_CurrentVersionRun_eee4 {
  strings:
    $key_eee4 = { bd 8b [2] 99 85 [2] b2 a9 [2] 9c 8b [2] 88 90 [2] 87 8a [2] 99 97 [2] 9b 96 [2] 80 90 [2] 9c 97 [2] 80 b8 }

  condition:
    any of them
}