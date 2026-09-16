rule TTP_XOR_QUAD_CurrentVersionRun_3a4c {
  strings:
    $key_3a4c = { 69 23 [2] 4d 2d [2] 66 01 [2] 48 23 [2] 5c 38 [2] 53 22 [2] 4d 3f [2] 4f 3e [2] 54 38 [2] 48 3f [2] 54 10 }

  condition:
    any of them
}