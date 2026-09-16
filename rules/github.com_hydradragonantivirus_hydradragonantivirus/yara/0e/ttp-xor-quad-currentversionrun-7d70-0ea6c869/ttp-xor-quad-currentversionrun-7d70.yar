rule TTP_XOR_QUAD_CurrentVersionRun_7d70 {
  strings:
    $key_7d70 = { 2e 1f [2] 0a 11 [2] 21 3d [2] 0f 1f [2] 1b 04 [2] 14 1e [2] 0a 03 [2] 08 02 [2] 13 04 [2] 0f 03 [2] 13 2c }

  condition:
    any of them
}