rule TTP_XOR_QUAD_CurrentVersionRun_1223 {
  strings:
    $key_1223 = { 41 4c [2] 65 42 [2] 4e 6e [2] 60 4c [2] 74 57 [2] 7b 4d [2] 65 50 [2] 67 51 [2] 7c 57 [2] 60 50 [2] 7c 7f }

  condition:
    any of them
}