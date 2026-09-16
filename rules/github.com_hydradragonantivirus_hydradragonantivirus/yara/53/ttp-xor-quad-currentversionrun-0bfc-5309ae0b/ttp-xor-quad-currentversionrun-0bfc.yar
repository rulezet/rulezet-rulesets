rule TTP_XOR_QUAD_CurrentVersionRun_0bfc {
  strings:
    $key_0bfc = { 58 93 [2] 7c 9d [2] 57 b1 [2] 79 93 [2] 6d 88 [2] 62 92 [2] 7c 8f [2] 7e 8e [2] 65 88 [2] 79 8f [2] 65 a0 }

  condition:
    any of them
}