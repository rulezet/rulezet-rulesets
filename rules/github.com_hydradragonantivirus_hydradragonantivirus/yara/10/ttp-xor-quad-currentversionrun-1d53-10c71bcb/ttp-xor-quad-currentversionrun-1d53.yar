rule TTP_XOR_QUAD_CurrentVersionRun_1d53 {
  strings:
    $key_1d53 = { 4e 3c [2] 6a 32 [2] 41 1e [2] 6f 3c [2] 7b 27 [2] 74 3d [2] 6a 20 [2] 68 21 [2] 73 27 [2] 6f 20 [2] 73 0f }

  condition:
    any of them
}