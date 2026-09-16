rule TTP_XOR_QUAD_CurrentVersionRun_f84c {
  strings:
    $key_f84c = { ab 23 [2] 8f 2d [2] a4 01 [2] 8a 23 [2] 9e 38 [2] 91 22 [2] 8f 3f [2] 8d 3e [2] 96 38 [2] 8a 3f [2] 96 10 }

  condition:
    any of them
}