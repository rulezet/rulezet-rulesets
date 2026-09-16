rule TTP_XOR_QUAD_CurrentVersionRun_41f9 {
  strings:
    $key_41f9 = { 12 96 [2] 36 98 [2] 1d b4 [2] 33 96 [2] 27 8d [2] 28 97 [2] 36 8a [2] 34 8b [2] 2f 8d [2] 33 8a [2] 2f a5 }

  condition:
    any of them
}