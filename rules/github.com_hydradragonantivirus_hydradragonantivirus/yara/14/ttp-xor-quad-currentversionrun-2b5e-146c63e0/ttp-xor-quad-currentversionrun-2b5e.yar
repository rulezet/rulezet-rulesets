rule TTP_XOR_QUAD_CurrentVersionRun_2b5e {
  strings:
    $key_2b5e = { 78 31 [2] 5c 3f [2] 77 13 [2] 59 31 [2] 4d 2a [2] 42 30 [2] 5c 2d [2] 5e 2c [2] 45 2a [2] 59 2d [2] 45 02 }

  condition:
    any of them
}