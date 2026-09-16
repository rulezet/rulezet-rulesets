rule TTP_XOR_QUAD_CurrentVersionRun_17fc {
  strings:
    $key_17fc = { 44 93 [2] 60 9d [2] 4b b1 [2] 65 93 [2] 71 88 [2] 7e 92 [2] 60 8f [2] 62 8e [2] 79 88 [2] 65 8f [2] 79 a0 }

  condition:
    any of them
}