rule TTP_XOR_QUAD_CurrentVersionRun_1163 {
  strings:
    $key_1163 = { 42 0c [2] 66 02 [2] 4d 2e [2] 63 0c [2] 77 17 [2] 78 0d [2] 66 10 [2] 64 11 [2] 7f 17 [2] 63 10 [2] 7f 3f }

  condition:
    any of them
}