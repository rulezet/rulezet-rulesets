rule TTP_XOR_QUAD_CurrentVersionRun_3c53 {
  strings:
    $key_3c53 = { 6f 3c [2] 4b 32 [2] 60 1e [2] 4e 3c [2] 5a 27 [2] 55 3d [2] 4b 20 [2] 49 21 [2] 52 27 [2] 4e 20 [2] 52 0f }

  condition:
    any of them
}