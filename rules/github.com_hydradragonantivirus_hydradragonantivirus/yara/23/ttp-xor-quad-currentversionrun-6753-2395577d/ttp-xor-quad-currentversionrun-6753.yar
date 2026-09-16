rule TTP_XOR_QUAD_CurrentVersionRun_6753 {
  strings:
    $key_6753 = { 34 3c [2] 10 32 [2] 3b 1e [2] 15 3c [2] 01 27 [2] 0e 3d [2] 10 20 [2] 12 21 [2] 09 27 [2] 15 20 [2] 09 0f }

  condition:
    any of them
}