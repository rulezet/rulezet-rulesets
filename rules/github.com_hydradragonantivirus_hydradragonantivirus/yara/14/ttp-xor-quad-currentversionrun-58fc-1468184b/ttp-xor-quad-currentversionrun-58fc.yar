rule TTP_XOR_QUAD_CurrentVersionRun_58fc {
  strings:
    $key_58fc = { 0b 93 [2] 2f 9d [2] 04 b1 [2] 2a 93 [2] 3e 88 [2] 31 92 [2] 2f 8f [2] 2d 8e [2] 36 88 [2] 2a 8f [2] 36 a0 }

  condition:
    any of them
}