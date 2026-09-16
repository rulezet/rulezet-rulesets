rule TTP_XOR_QUAD_CurrentVersionRun_4a30 {
  strings:
    $key_4a30 = { 19 5f [2] 3d 51 [2] 16 7d [2] 38 5f [2] 2c 44 [2] 23 5e [2] 3d 43 [2] 3f 42 [2] 24 44 [2] 38 43 [2] 24 6c }

  condition:
    any of them
}