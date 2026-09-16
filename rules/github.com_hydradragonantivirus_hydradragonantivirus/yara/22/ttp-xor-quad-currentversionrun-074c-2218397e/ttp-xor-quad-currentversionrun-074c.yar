rule TTP_XOR_QUAD_CurrentVersionRun_074c {
  strings:
    $key_074c = { 54 23 [2] 70 2d [2] 5b 01 [2] 75 23 [2] 61 38 [2] 6e 22 [2] 70 3f [2] 72 3e [2] 69 38 [2] 75 3f [2] 69 10 }

  condition:
    any of them
}