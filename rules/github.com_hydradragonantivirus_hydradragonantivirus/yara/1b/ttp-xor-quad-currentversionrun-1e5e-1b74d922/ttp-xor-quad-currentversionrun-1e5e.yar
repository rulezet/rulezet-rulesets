rule TTP_XOR_QUAD_CurrentVersionRun_1e5e {
  strings:
    $key_1e5e = { 4d 31 [2] 69 3f [2] 42 13 [2] 6c 31 [2] 78 2a [2] 77 30 [2] 69 2d [2] 6b 2c [2] 70 2a [2] 6c 2d [2] 70 02 }

  condition:
    any of them
}