rule TTP_XOR_QUAD_CurrentVersionRun_0efc {
  strings:
    $key_0efc = { 5d 93 [2] 79 9d [2] 52 b1 [2] 7c 93 [2] 68 88 [2] 67 92 [2] 79 8f [2] 7b 8e [2] 60 88 [2] 7c 8f [2] 60 a0 }

  condition:
    any of them
}