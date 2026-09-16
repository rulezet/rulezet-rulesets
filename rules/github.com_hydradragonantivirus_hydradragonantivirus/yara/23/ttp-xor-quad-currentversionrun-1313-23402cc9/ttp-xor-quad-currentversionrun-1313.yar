rule TTP_XOR_QUAD_CurrentVersionRun_1313 {
  strings:
    $key_1313 = { 40 7c [2] 64 72 [2] 4f 5e [2] 61 7c [2] 75 67 [2] 7a 7d [2] 64 60 [2] 66 61 [2] 7d 67 [2] 61 60 [2] 7d 4f }

  condition:
    any of them
}