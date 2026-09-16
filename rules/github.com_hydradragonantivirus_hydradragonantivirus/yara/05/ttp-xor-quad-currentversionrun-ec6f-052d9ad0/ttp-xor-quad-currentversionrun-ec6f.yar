rule TTP_XOR_QUAD_CurrentVersionRun_ec6f {
  strings:
    $key_ec6f = { bf 00 [2] 9b 0e [2] b0 22 [2] 9e 00 [2] 8a 1b [2] 85 01 [2] 9b 1c [2] 99 1d [2] 82 1b [2] 9e 1c [2] 82 33 }

  condition:
    any of them
}