rule TTP_XOR_QUAD_CurrentVersionRun_3270 {
  strings:
    $key_3270 = { 61 1f [2] 45 11 [2] 6e 3d [2] 40 1f [2] 54 04 [2] 5b 1e [2] 45 03 [2] 47 02 [2] 5c 04 [2] 40 03 [2] 5c 2c }

  condition:
    any of them
}