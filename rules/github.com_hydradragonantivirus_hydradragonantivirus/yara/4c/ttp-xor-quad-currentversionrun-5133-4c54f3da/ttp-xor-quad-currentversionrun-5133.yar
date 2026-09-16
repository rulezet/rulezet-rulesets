rule TTP_XOR_QUAD_CurrentVersionRun_5133 {
  strings:
    $key_5133 = { 02 5c [2] 26 52 [2] 0d 7e [2] 23 5c [2] 37 47 [2] 38 5d [2] 26 40 [2] 24 41 [2] 3f 47 [2] 23 40 [2] 3f 6f }

  condition:
    any of them
}