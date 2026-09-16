rule TTP_XOR_QUAD_CurrentVersionRun_4d0d {
  strings:
    $key_4d0d = { 1e 62 [2] 3a 6c [2] 11 40 [2] 3f 62 [2] 2b 79 [2] 24 63 [2] 3a 7e [2] 38 7f [2] 23 79 [2] 3f 7e [2] 23 51 }

  condition:
    any of them
}