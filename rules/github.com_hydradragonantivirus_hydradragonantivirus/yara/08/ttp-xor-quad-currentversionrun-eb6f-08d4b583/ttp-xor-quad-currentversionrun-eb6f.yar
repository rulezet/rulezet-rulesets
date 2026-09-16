rule TTP_XOR_QUAD_CurrentVersionRun_eb6f {
  strings:
    $key_eb6f = { b8 00 [2] 9c 0e [2] b7 22 [2] 99 00 [2] 8d 1b [2] 82 01 [2] 9c 1c [2] 9e 1d [2] 85 1b [2] 99 1c [2] 85 33 }

  condition:
    any of them
}