rule TTP_XOR_QUAD_CurrentVersionRun_2ffc {
  strings:
    $key_2ffc = { 7c 93 [2] 58 9d [2] 73 b1 [2] 5d 93 [2] 49 88 [2] 46 92 [2] 58 8f [2] 5a 8e [2] 41 88 [2] 5d 8f [2] 41 a0 }

  condition:
    any of them
}