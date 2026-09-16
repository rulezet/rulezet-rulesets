rule TTP_XOR_QUAD_CurrentVersionRun_521f {
  strings:
    $key_521f = { 01 70 [2] 25 7e [2] 0e 52 [2] 20 70 [2] 34 6b [2] 3b 71 [2] 25 6c [2] 27 6d [2] 3c 6b [2] 20 6c [2] 3c 43 }

  condition:
    any of them
}