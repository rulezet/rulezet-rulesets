rule TTP_XOR_QUAD_CurrentVersionRun_51fc {
  strings:
    $key_51fc = { 02 93 [2] 26 9d [2] 0d b1 [2] 23 93 [2] 37 88 [2] 38 92 [2] 26 8f [2] 24 8e [2] 3f 88 [2] 23 8f [2] 3f a0 }

  condition:
    any of them
}