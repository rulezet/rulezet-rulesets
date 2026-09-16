rule TTP_XOR_QUAD_CurrentVersionRun_eb6e {
  strings:
    $key_eb6e = { b8 01 [2] 9c 0f [2] b7 23 [2] 99 01 [2] 8d 1a [2] 82 00 [2] 9c 1d [2] 9e 1c [2] 85 1a [2] 99 1d [2] 85 32 }

  condition:
    any of them
}