rule TTP_XOR_QUAD_CurrentVersionRun_1753 {
  strings:
    $key_1753 = { 44 3c [2] 60 32 [2] 4b 1e [2] 65 3c [2] 71 27 [2] 7e 3d [2] 60 20 [2] 62 21 [2] 79 27 [2] 65 20 [2] 79 0f }

  condition:
    any of them
}