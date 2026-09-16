rule TTP_XOR_QUAD_CurrentVersionRun_3d4c {
  strings:
    $key_3d4c = { 6e 23 [2] 4a 2d [2] 61 01 [2] 4f 23 [2] 5b 38 [2] 54 22 [2] 4a 3f [2] 48 3e [2] 53 38 [2] 4f 3f [2] 53 10 }

  condition:
    any of them
}