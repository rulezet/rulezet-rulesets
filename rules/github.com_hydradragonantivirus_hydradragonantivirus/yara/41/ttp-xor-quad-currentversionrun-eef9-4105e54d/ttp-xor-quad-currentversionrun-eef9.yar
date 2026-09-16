rule TTP_XOR_QUAD_CurrentVersionRun_eef9 {
  strings:
    $key_eef9 = { bd 96 [2] 99 98 [2] b2 b4 [2] 9c 96 [2] 88 8d [2] 87 97 [2] 99 8a [2] 9b 8b [2] 80 8d [2] 9c 8a [2] 80 a5 }

  condition:
    any of them
}