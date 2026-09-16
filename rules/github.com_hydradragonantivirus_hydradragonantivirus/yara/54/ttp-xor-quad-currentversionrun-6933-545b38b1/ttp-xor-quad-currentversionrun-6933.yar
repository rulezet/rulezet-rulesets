rule TTP_XOR_QUAD_CurrentVersionRun_6933 {
  strings:
    $key_6933 = { 3a 5c [2] 1e 52 [2] 35 7e [2] 1b 5c [2] 0f 47 [2] 00 5d [2] 1e 40 [2] 1c 41 [2] 07 47 [2] 1b 40 [2] 07 6f }

  condition:
    any of them
}