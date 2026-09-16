rule TTP_XOR_QUAD_CurrentVersionRun_564c {
  strings:
    $key_564c = { 05 23 [2] 21 2d [2] 0a 01 [2] 24 23 [2] 30 38 [2] 3f 22 [2] 21 3f [2] 23 3e [2] 38 38 [2] 24 3f [2] 38 10 }

  condition:
    any of them
}