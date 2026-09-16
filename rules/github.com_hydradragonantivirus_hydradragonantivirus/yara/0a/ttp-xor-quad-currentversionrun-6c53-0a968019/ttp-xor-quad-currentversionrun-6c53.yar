rule TTP_XOR_QUAD_CurrentVersionRun_6c53 {
  strings:
    $key_6c53 = { 3f 3c [2] 1b 32 [2] 30 1e [2] 1e 3c [2] 0a 27 [2] 05 3d [2] 1b 20 [2] 19 21 [2] 02 27 [2] 1e 20 [2] 02 0f }

  condition:
    any of them
}