rule TTP_XOR_QUAD_CurrentVersionRun_4dfc {
  strings:
    $key_4dfc = { 1e 93 [2] 3a 9d [2] 11 b1 [2] 3f 93 [2] 2b 88 [2] 24 92 [2] 3a 8f [2] 38 8e [2] 23 88 [2] 3f 8f [2] 23 a0 }

  condition:
    any of them
}