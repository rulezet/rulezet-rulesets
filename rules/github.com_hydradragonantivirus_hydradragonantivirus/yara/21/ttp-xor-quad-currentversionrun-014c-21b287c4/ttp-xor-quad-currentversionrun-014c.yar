rule TTP_XOR_QUAD_CurrentVersionRun_014c {
  strings:
    $key_014c = { 52 23 [2] 76 2d [2] 5d 01 [2] 73 23 [2] 67 38 [2] 68 22 [2] 76 3f [2] 74 3e [2] 6f 38 [2] 73 3f [2] 6f 10 }

  condition:
    any of them
}