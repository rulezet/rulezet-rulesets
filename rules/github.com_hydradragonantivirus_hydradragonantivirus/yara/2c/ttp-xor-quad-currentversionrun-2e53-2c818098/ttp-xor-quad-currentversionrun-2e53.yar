rule TTP_XOR_QUAD_CurrentVersionRun_2e53 {
  strings:
    $key_2e53 = { 7d 3c [2] 59 32 [2] 72 1e [2] 5c 3c [2] 48 27 [2] 47 3d [2] 59 20 [2] 5b 21 [2] 40 27 [2] 5c 20 [2] 40 0f }

  condition:
    any of them
}