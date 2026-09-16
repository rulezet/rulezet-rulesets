rule TTP_XOR_QUAD_CurrentVersionRun_2d63 {
  strings:
    $key_2d63 = { 7e 0c [2] 5a 02 [2] 71 2e [2] 5f 0c [2] 4b 17 [2] 44 0d [2] 5a 10 [2] 58 11 [2] 43 17 [2] 5f 10 [2] 43 3f }

  condition:
    any of them
}