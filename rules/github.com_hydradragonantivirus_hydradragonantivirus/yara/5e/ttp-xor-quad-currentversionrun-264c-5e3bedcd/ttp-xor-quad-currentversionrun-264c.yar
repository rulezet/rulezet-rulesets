rule TTP_XOR_QUAD_CurrentVersionRun_264c {
  strings:
    $key_264c = { 75 23 [2] 51 2d [2] 7a 01 [2] 54 23 [2] 40 38 [2] 4f 22 [2] 51 3f [2] 53 3e [2] 48 38 [2] 54 3f [2] 48 10 }

  condition:
    any of them
}