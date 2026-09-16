rule TTP_XOR_QUAD_CurrentVersionRun_1371 {
  strings:
    $key_1371 = { 40 1e [2] 64 10 [2] 4f 3c [2] 61 1e [2] 75 05 [2] 7a 1f [2] 64 02 [2] 66 03 [2] 7d 05 [2] 61 02 [2] 7d 2d }

  condition:
    any of them
}