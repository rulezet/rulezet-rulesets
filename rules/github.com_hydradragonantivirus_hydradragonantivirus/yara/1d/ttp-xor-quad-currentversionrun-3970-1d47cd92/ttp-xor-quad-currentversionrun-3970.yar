rule TTP_XOR_QUAD_CurrentVersionRun_3970 {
  strings:
    $key_3970 = { 6a 1f [2] 4e 11 [2] 65 3d [2] 4b 1f [2] 5f 04 [2] 50 1e [2] 4e 03 [2] 4c 02 [2] 57 04 [2] 4b 03 [2] 57 2c }

  condition:
    any of them
}