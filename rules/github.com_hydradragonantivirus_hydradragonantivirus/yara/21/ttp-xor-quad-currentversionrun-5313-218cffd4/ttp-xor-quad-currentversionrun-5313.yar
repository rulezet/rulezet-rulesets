rule TTP_XOR_QUAD_CurrentVersionRun_5313 {
  strings:
    $key_5313 = { 00 7c [2] 24 72 [2] 0f 5e [2] 21 7c [2] 35 67 [2] 3a 7d [2] 24 60 [2] 26 61 [2] 3d 67 [2] 21 60 [2] 3d 4f }

  condition:
    any of them
}