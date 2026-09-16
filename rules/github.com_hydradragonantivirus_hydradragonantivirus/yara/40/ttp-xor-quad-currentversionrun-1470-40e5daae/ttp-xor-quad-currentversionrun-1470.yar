rule TTP_XOR_QUAD_CurrentVersionRun_1470 {
  strings:
    $key_1470 = { 47 1f [2] 63 11 [2] 48 3d [2] 66 1f [2] 72 04 [2] 7d 1e [2] 63 03 [2] 61 02 [2] 7a 04 [2] 66 03 [2] 7a 2c }

  condition:
    any of them
}