rule TTP_XOR_QUAD_CurrentVersionRun_114c {
  strings:
    $key_114c = { 42 23 [2] 66 2d [2] 4d 01 [2] 63 23 [2] 77 38 [2] 78 22 [2] 66 3f [2] 64 3e [2] 7f 38 [2] 63 3f [2] 7f 10 }

  condition:
    any of them
}