rule TTP_XOR_QUAD_CurrentVersionRun_432d {
  strings:
    $key_432d = { 10 42 [2] 34 4c [2] 1f 60 [2] 31 42 [2] 25 59 [2] 2a 43 [2] 34 5e [2] 36 5f [2] 2d 59 [2] 31 5e [2] 2d 71 }

  condition:
    any of them
}