rule TTP_XOR_QUAD_CurrentVersionRun_7653 {
  strings:
    $key_7653 = { 25 3c [2] 01 32 [2] 2a 1e [2] 04 3c [2] 10 27 [2] 1f 3d [2] 01 20 [2] 03 21 [2] 18 27 [2] 04 20 [2] 18 0f }

  condition:
    any of them
}