rule TTP_XOR_QUAD_CurrentVersionRun_0953 {
  strings:
    $key_0953 = { 5a 3c [2] 7e 32 [2] 55 1e [2] 7b 3c [2] 6f 27 [2] 60 3d [2] 7e 20 [2] 7c 21 [2] 67 27 [2] 7b 20 [2] 67 0f }

  condition:
    any of them
}