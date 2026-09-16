rule TTP_XOR_QUAD_CurrentVersionRun_66fc {
  strings:
    $key_66fc = { 35 93 [2] 11 9d [2] 3a b1 [2] 14 93 [2] 00 88 [2] 0f 92 [2] 11 8f [2] 13 8e [2] 08 88 [2] 14 8f [2] 08 a0 }

  condition:
    any of them
}