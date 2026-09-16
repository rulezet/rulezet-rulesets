rule TTP_XOR_QUAD_CurrentVersionRun_2b4e {
  strings:
    $key_2b4e = { 78 21 [2] 5c 2f [2] 77 03 [2] 59 21 [2] 4d 3a [2] 42 20 [2] 5c 3d [2] 5e 3c [2] 45 3a [2] 59 3d [2] 45 12 }

  condition:
    any of them
}