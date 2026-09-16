rule TTP_XOR_QUAD_CurrentVersionRun_3c4c {
  strings:
    $key_3c4c = { 6f 23 [2] 4b 2d [2] 60 01 [2] 4e 23 [2] 5a 38 [2] 55 22 [2] 4b 3f [2] 49 3e [2] 52 38 [2] 4e 3f [2] 52 10 }

  condition:
    any of them
}