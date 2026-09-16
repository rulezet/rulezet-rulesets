rule TTP_XOR_QUAD_CurrentVersionRun_75ec {
  strings:
    $key_75ec = { 26 83 [2] 02 8d [2] 29 a1 [2] 07 83 [2] 13 98 [2] 1c 82 [2] 02 9f [2] 00 9e [2] 1b 98 [2] 07 9f [2] 1b b0 }

  condition:
    any of them
}