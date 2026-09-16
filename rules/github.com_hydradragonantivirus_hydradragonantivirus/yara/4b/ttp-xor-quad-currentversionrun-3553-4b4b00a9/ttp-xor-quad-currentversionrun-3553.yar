rule TTP_XOR_QUAD_CurrentVersionRun_3553 {
  strings:
    $key_3553 = { 66 3c [2] 42 32 [2] 69 1e [2] 47 3c [2] 53 27 [2] 5c 3d [2] 42 20 [2] 40 21 [2] 5b 27 [2] 47 20 [2] 5b 0f }

  condition:
    any of them
}