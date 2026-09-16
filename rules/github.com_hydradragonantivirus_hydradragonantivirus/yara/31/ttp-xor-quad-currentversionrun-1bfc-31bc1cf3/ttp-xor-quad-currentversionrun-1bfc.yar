rule TTP_XOR_QUAD_CurrentVersionRun_1bfc {
  strings:
    $key_1bfc = { 48 93 [2] 6c 9d [2] 47 b1 [2] 69 93 [2] 7d 88 [2] 72 92 [2] 6c 8f [2] 6e 8e [2] 75 88 [2] 69 8f [2] 75 a0 }

  condition:
    any of them
}