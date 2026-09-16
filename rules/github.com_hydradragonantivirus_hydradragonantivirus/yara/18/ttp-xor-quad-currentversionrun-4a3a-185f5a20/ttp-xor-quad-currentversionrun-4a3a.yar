rule TTP_XOR_QUAD_CurrentVersionRun_4a3a {
  strings:
    $key_4a3a = { 19 55 [2] 3d 5b [2] 16 77 [2] 38 55 [2] 2c 4e [2] 23 54 [2] 3d 49 [2] 3f 48 [2] 24 4e [2] 38 49 [2] 24 66 }

  condition:
    any of them
}