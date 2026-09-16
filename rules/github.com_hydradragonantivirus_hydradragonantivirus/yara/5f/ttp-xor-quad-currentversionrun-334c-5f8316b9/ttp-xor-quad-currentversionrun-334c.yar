rule TTP_XOR_QUAD_CurrentVersionRun_334c {
  strings:
    $key_334c = { 60 23 [2] 44 2d [2] 6f 01 [2] 41 23 [2] 55 38 [2] 5a 22 [2] 44 3f [2] 46 3e [2] 5d 38 [2] 41 3f [2] 5d 10 }

  condition:
    any of them
}