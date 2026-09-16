rule TTP_XOR_QUAD_CurrentVersionRun_eee5 {
  strings:
    $key_eee5 = { bd 8a [2] 99 84 [2] b2 a8 [2] 9c 8a [2] 88 91 [2] 87 8b [2] 99 96 [2] 9b 97 [2] 80 91 [2] 9c 96 [2] 80 b9 }

  condition:
    any of them
}