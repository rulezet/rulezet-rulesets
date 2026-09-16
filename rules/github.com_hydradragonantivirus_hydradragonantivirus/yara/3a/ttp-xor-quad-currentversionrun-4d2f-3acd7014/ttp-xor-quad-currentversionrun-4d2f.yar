rule TTP_XOR_QUAD_CurrentVersionRun_4d2f {
  strings:
    $key_4d2f = { 1e 40 [2] 3a 4e [2] 11 62 [2] 3f 40 [2] 2b 5b [2] 24 41 [2] 3a 5c [2] 38 5d [2] 23 5b [2] 3f 5c [2] 23 73 }

  condition:
    any of them
}