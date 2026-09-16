rule TTP_XOR_QUAD_CurrentVersionRun_dd53 {
  strings:
    $key_dd53 = { 8e 3c [2] aa 32 [2] 81 1e [2] af 3c [2] bb 27 [2] b4 3d [2] aa 20 [2] a8 21 [2] b3 27 [2] af 20 [2] b3 0f }

  condition:
    any of them
}