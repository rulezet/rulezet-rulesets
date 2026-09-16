rule TTP_XOR_QUAD_CurrentVersionRun_0b33 {
  strings:
    $key_0b33 = { 58 5c [2] 7c 52 [2] 57 7e [2] 79 5c [2] 6d 47 [2] 62 5d [2] 7c 40 [2] 7e 41 [2] 65 47 [2] 79 40 [2] 65 6f }

  condition:
    any of them
}