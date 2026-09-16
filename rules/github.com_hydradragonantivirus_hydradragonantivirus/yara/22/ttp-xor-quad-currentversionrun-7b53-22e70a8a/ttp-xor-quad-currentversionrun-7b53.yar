rule TTP_XOR_QUAD_CurrentVersionRun_7b53 {
  strings:
    $key_7b53 = { 28 3c [2] 0c 32 [2] 27 1e [2] 09 3c [2] 1d 27 [2] 12 3d [2] 0c 20 [2] 0e 21 [2] 15 27 [2] 09 20 [2] 15 0f }

  condition:
    any of them
}