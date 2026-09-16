rule TTP_XOR_QUAD_CurrentVersionRun_2d7f {
  strings:
    $key_2d7f = { 7e 10 [2] 5a 1e [2] 71 32 [2] 5f 10 [2] 4b 0b [2] 44 11 [2] 5a 0c [2] 58 0d [2] 43 0b [2] 5f 0c [2] 43 23 }

  condition:
    any of them
}