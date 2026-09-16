rule TTP_XOR_QUAD_CurrentVersionRun_0850 {
  strings:
    $key_0850 = { 5b 3f [2] 7f 31 [2] 54 1d [2] 7a 3f [2] 6e 24 [2] 61 3e [2] 7f 23 [2] 7d 22 [2] 66 24 [2] 7a 23 [2] 66 0c }

  condition:
    any of them
}