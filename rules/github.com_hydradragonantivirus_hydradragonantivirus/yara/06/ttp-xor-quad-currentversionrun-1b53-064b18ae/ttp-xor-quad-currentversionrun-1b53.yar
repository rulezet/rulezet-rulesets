rule TTP_XOR_QUAD_CurrentVersionRun_1b53 {
  strings:
    $key_1b53 = { 48 3c [2] 6c 32 [2] 47 1e [2] 69 3c [2] 7d 27 [2] 72 3d [2] 6c 20 [2] 6e 21 [2] 75 27 [2] 69 20 [2] 75 0f }

  condition:
    any of them
}