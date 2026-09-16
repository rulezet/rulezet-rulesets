rule TTP_XOR_QUAD_CurrentVersionRun_4c53 {
  strings:
    $key_4c53 = { 1f 3c [2] 3b 32 [2] 10 1e [2] 3e 3c [2] 2a 27 [2] 25 3d [2] 3b 20 [2] 39 21 [2] 22 27 [2] 3e 20 [2] 22 0f }

  condition:
    any of them
}