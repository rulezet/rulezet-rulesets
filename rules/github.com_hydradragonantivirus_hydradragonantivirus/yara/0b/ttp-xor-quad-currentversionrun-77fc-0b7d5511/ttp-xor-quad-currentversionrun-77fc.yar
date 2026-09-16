rule TTP_XOR_QUAD_CurrentVersionRun_77fc {
  strings:
    $key_77fc = { 24 93 [2] 00 9d [2] 2b b1 [2] 05 93 [2] 11 88 [2] 1e 92 [2] 00 8f [2] 02 8e [2] 19 88 [2] 05 8f [2] 19 a0 }

  condition:
    any of them
}