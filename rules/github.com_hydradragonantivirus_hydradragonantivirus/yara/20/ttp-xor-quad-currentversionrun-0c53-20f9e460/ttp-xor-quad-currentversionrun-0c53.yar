rule TTP_XOR_QUAD_CurrentVersionRun_0c53 {
  strings:
    $key_0c53 = { 5f 3c [2] 7b 32 [2] 50 1e [2] 7e 3c [2] 6a 27 [2] 65 3d [2] 7b 20 [2] 79 21 [2] 62 27 [2] 7e 20 [2] 62 0f }

  condition:
    any of them
}