rule TTP_XOR_QUAD_CurrentVersionRun_75fc {
  strings:
    $key_75fc = { 26 93 [2] 02 9d [2] 29 b1 [2] 07 93 [2] 13 88 [2] 1c 92 [2] 02 8f [2] 00 8e [2] 1b 88 [2] 07 8f [2] 1b a0 }

  condition:
    any of them
}