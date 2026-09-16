rule TTP_XOR_QUAD_CurrentVersionRun_4d2d {
  strings:
    $key_4d2d = { 1e 42 [2] 3a 4c [2] 11 60 [2] 3f 42 [2] 2b 59 [2] 24 43 [2] 3a 5e [2] 38 5f [2] 23 59 [2] 3f 5e [2] 23 71 }

  condition:
    any of them
}