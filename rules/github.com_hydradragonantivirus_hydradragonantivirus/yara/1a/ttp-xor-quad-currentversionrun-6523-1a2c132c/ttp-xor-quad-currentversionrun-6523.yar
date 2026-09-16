rule TTP_XOR_QUAD_CurrentVersionRun_6523 {
  strings:
    $key_6523 = { 36 4c [2] 12 42 [2] 39 6e [2] 17 4c [2] 03 57 [2] 0c 4d [2] 12 50 [2] 10 51 [2] 0b 57 [2] 17 50 [2] 0b 7f }

  condition:
    any of them
}