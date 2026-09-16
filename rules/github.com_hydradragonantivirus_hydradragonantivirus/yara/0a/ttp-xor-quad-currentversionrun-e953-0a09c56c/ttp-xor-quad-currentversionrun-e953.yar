rule TTP_XOR_QUAD_CurrentVersionRun_e953 {
  strings:
    $key_e953 = { ba 3c [2] 9e 32 [2] b5 1e [2] 9b 3c [2] 8f 27 [2] 80 3d [2] 9e 20 [2] 9c 21 [2] 87 27 [2] 9b 20 [2] 87 0f }

  condition:
    any of them
}