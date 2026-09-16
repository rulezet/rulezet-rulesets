rule TTP_XOR_QUAD_CurrentVersionRun_c453 {
  strings:
    $key_c453 = { 97 3c [2] b3 32 [2] 98 1e [2] b6 3c [2] a2 27 [2] ad 3d [2] b3 20 [2] b1 21 [2] aa 27 [2] b6 20 [2] aa 0f }

  condition:
    any of them
}