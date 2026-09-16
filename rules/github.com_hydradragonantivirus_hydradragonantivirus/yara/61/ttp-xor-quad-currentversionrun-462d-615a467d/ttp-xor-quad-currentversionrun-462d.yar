rule TTP_XOR_QUAD_CurrentVersionRun_462d {
  strings:
    $key_462d = { 15 42 [2] 31 4c [2] 1a 60 [2] 34 42 [2] 20 59 [2] 2f 43 [2] 31 5e [2] 33 5f [2] 28 59 [2] 34 5e [2] 28 71 }

  condition:
    any of them
}