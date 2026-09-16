rule TTP_XOR_QUAD_CurrentVersionRun_6670 {
  strings:
    $key_6670 = { 35 1f [2] 11 11 [2] 3a 3d [2] 14 1f [2] 00 04 [2] 0f 1e [2] 11 03 [2] 13 02 [2] 08 04 [2] 14 03 [2] 08 2c }

  condition:
    any of them
}