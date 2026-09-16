rule TTP_XOR_QUAD_CurrentVersionRun_687f {
  strings:
    $key_687f = { 3b 10 [2] 1f 1e [2] 34 32 [2] 1a 10 [2] 0e 0b [2] 01 11 [2] 1f 0c [2] 1d 0d [2] 06 0b [2] 1a 0c [2] 06 23 }

  condition:
    any of them
}