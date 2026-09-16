rule TTP_XOR_QUAD_CurrentVersionRun_4c4c {
  strings:
    $key_4c4c = { 1f 23 [2] 3b 2d [2] 10 01 [2] 3e 23 [2] 2a 38 [2] 25 22 [2] 3b 3f [2] 39 3e [2] 22 38 [2] 3e 3f [2] 22 10 }

  condition:
    any of them
}