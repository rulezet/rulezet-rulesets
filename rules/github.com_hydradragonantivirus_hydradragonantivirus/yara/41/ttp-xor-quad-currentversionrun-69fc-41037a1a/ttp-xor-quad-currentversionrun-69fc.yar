rule TTP_XOR_QUAD_CurrentVersionRun_69fc {
  strings:
    $key_69fc = { 3a 93 [2] 1e 9d [2] 35 b1 [2] 1b 93 [2] 0f 88 [2] 00 92 [2] 1e 8f [2] 1c 8e [2] 07 88 [2] 1b 8f [2] 07 a0 }

  condition:
    any of them
}