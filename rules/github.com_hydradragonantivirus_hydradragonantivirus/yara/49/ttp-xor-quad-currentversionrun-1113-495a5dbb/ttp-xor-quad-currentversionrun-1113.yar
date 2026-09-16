rule TTP_XOR_QUAD_CurrentVersionRun_1113 {
  strings:
    $key_1113 = { 42 7c [2] 66 72 [2] 4d 5e [2] 63 7c [2] 77 67 [2] 78 7d [2] 66 60 [2] 64 61 [2] 7f 67 [2] 63 60 [2] 7f 4f }

  condition:
    any of them
}