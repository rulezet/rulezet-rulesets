rule TTP_XOR_QUAD_CurrentVersionRun_0d70 {
  strings:
    $key_0d70 = { 5e 1f [2] 7a 11 [2] 51 3d [2] 7f 1f [2] 6b 04 [2] 64 1e [2] 7a 03 [2] 78 02 [2] 63 04 [2] 7f 03 [2] 63 2c }

  condition:
    any of them
}