rule TTP_XOR_QUAD_CurrentVersionRun_681f {
  strings:
    $key_681f = { 3b 70 [2] 1f 7e [2] 34 52 [2] 1a 70 [2] 0e 6b [2] 01 71 [2] 1f 6c [2] 1d 6d [2] 06 6b [2] 1a 6c [2] 06 43 }

  condition:
    any of them
}