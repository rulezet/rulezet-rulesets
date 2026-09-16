rule TTP_XOR_QUAD_CurrentVersionRun_1270 {
  strings:
    $key_1270 = { 41 1f [2] 65 11 [2] 4e 3d [2] 60 1f [2] 74 04 [2] 7b 1e [2] 65 03 [2] 67 02 [2] 7c 04 [2] 60 03 [2] 7c 2c }

  condition:
    any of them
}