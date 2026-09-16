rule TTP_XOR_QUAD_CurrentVersionRun_0553 {
  strings:
    $key_0553 = { 56 3c [2] 72 32 [2] 59 1e [2] 77 3c [2] 63 27 [2] 6c 3d [2] 72 20 [2] 70 21 [2] 6b 27 [2] 77 20 [2] 6b 0f }

  condition:
    any of them
}