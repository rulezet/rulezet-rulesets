rule TTP_XOR_QUAD_CurrentVersionRun_0d53 {
  strings:
    $key_0d53 = { 5e 3c [2] 7a 32 [2] 51 1e [2] 7f 3c [2] 6b 27 [2] 64 3d [2] 7a 20 [2] 78 21 [2] 63 27 [2] 7f 20 [2] 63 0f }

  condition:
    any of them
}