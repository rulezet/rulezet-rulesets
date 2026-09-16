rule TTP_XOR_QUAD_CurrentVersionRun_1670 {
  strings:
    $key_1670 = { 45 1f [2] 61 11 [2] 4a 3d [2] 64 1f [2] 70 04 [2] 7f 1e [2] 61 03 [2] 63 02 [2] 78 04 [2] 64 03 [2] 78 2c }

  condition:
    any of them
}