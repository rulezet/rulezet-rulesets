rule TTP_XOR_QUAD_CurrentVersionRun_41fc {
  strings:
    $key_41fc = { 12 93 [2] 36 9d [2] 1d b1 [2] 33 93 [2] 27 88 [2] 28 92 [2] 36 8f [2] 34 8e [2] 2f 88 [2] 33 8f [2] 2f a0 }

  condition:
    any of them
}