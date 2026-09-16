rule TTP_XOR_QUAD_CurrentVersionRun_1153 {
  strings:
    $key_1153 = { 42 3c [2] 66 32 [2] 4d 1e [2] 63 3c [2] 77 27 [2] 78 3d [2] 66 20 [2] 64 21 [2] 7f 27 [2] 63 20 [2] 7f 0f }

  condition:
    any of them
}