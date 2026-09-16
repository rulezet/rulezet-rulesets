rule TTP_XOR_QUAD_CurrentVersionRun_5d1f {
  strings:
    $key_5d1f = { 0e 70 [2] 2a 7e [2] 01 52 [2] 2f 70 [2] 3b 6b [2] 34 71 [2] 2a 6c [2] 28 6d [2] 33 6b [2] 2f 6c [2] 33 43 }

  condition:
    any of them
}