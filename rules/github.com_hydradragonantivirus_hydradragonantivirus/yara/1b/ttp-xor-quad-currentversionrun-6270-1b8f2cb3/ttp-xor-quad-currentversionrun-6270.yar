rule TTP_XOR_QUAD_CurrentVersionRun_6270 {
  strings:
    $key_6270 = { 31 1f [2] 15 11 [2] 3e 3d [2] 10 1f [2] 04 04 [2] 0b 1e [2] 15 03 [2] 17 02 [2] 0c 04 [2] 10 03 [2] 0c 2c }

  condition:
    any of them
}