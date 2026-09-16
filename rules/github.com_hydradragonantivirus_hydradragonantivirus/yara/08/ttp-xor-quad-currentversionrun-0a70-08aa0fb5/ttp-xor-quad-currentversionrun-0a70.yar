rule TTP_XOR_QUAD_CurrentVersionRun_0a70 {
  strings:
    $key_0a70 = { 59 1f [2] 7d 11 [2] 56 3d [2] 78 1f [2] 6c 04 [2] 63 1e [2] 7d 03 [2] 7f 02 [2] 64 04 [2] 78 03 [2] 64 2c }

  condition:
    any of them
}