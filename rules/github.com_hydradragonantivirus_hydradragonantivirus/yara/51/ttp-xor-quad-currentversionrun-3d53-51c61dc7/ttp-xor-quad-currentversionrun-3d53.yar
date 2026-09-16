rule TTP_XOR_QUAD_CurrentVersionRun_3d53 {
  strings:
    $key_3d53 = { 6e 3c [2] 4a 32 [2] 61 1e [2] 4f 3c [2] 5b 27 [2] 54 3d [2] 4a 20 [2] 48 21 [2] 53 27 [2] 4f 20 [2] 53 0f }

  condition:
    any of them
}