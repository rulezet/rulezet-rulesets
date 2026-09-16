rule TTP_XOR_QUAD_CurrentVersionRun_1253 {
  strings:
    $key_1253 = { 41 3c [2] 65 32 [2] 4e 1e [2] 60 3c [2] 74 27 [2] 7b 3d [2] 65 20 [2] 67 21 [2] 7c 27 [2] 60 20 [2] 7c 0f }

  condition:
    any of them
}