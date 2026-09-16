rule TTP_XOR_QUAD_CurrentVersionRun_0370 {
  strings:
    $key_0370 = { 50 1f [2] 74 11 [2] 5f 3d [2] 71 1f [2] 65 04 [2] 6a 1e [2] 74 03 [2] 76 02 [2] 6d 04 [2] 71 03 [2] 6d 2c }

  condition:
    any of them
}