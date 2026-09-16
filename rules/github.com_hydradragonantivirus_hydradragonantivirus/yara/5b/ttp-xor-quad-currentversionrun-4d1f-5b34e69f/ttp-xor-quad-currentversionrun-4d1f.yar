rule TTP_XOR_QUAD_CurrentVersionRun_4d1f {
  strings:
    $key_4d1f = { 1e 70 [2] 3a 7e [2] 11 52 [2] 3f 70 [2] 2b 6b [2] 24 71 [2] 3a 6c [2] 38 6d [2] 23 6b [2] 3f 6c [2] 23 43 }

  condition:
    any of them
}