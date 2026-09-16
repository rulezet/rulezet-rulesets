rule TTP_XOR_QUAD_CurrentVersionRun_1970 {
  strings:
    $key_1970 = { 4a 1f [2] 6e 11 [2] 45 3d [2] 6b 1f [2] 7f 04 [2] 70 1e [2] 6e 03 [2] 6c 02 [2] 77 04 [2] 6b 03 [2] 77 2c }

  condition:
    any of them
}