rule TTP_XOR_QUAD_CurrentVersionRun_7bfc {
  strings:
    $key_7bfc = { 28 93 [2] 0c 9d [2] 27 b1 [2] 09 93 [2] 1d 88 [2] 12 92 [2] 0c 8f [2] 0e 8e [2] 15 88 [2] 09 8f [2] 15 a0 }

  condition:
    any of them
}