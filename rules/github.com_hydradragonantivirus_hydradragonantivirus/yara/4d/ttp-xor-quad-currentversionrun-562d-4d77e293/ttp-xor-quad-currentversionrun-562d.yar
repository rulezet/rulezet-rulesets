rule TTP_XOR_QUAD_CurrentVersionRun_562d {
  strings:
    $key_562d = { 05 42 [2] 21 4c [2] 0a 60 [2] 24 42 [2] 30 59 [2] 3f 43 [2] 21 5e [2] 23 5f [2] 38 59 [2] 24 5e [2] 38 71 }

  condition:
    any of them
}