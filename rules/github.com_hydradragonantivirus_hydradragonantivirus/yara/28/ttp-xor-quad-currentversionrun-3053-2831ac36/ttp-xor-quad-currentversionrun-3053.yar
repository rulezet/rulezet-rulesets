rule TTP_XOR_QUAD_CurrentVersionRun_3053 {
  strings:
    $key_3053 = { 63 3c [2] 47 32 [2] 6c 1e [2] 42 3c [2] 56 27 [2] 59 3d [2] 47 20 [2] 45 21 [2] 5e 27 [2] 42 20 [2] 5e 0f }

  condition:
    any of them
}