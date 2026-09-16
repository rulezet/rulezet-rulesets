rule TTP_XOR_QUAD_CurrentVersionRun_1203 {
  strings:
    $key_1203 = { 41 6c [2] 65 62 [2] 4e 4e [2] 60 6c [2] 74 77 [2] 7b 6d [2] 65 70 [2] 67 71 [2] 7c 77 [2] 60 70 [2] 7c 5f }

  condition:
    any of them
}