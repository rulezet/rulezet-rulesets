rule TTP_XOR_QUAD_CurrentVersionRun_2e70 {
  strings:
    $key_2e70 = { 7d 1f [2] 59 11 [2] 72 3d [2] 5c 1f [2] 48 04 [2] 47 1e [2] 59 03 [2] 5b 02 [2] 40 04 [2] 5c 03 [2] 40 2c }

  condition:
    any of them
}