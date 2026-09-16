rule TTP_XOR_QUAD_CurrentVersionRun_ee6e {
  strings:
    $key_ee6e = { bd 01 [2] 99 0f [2] b2 23 [2] 9c 01 [2] 88 1a [2] 87 00 [2] 99 1d [2] 9b 1c [2] 80 1a [2] 9c 1d [2] 80 32 }

  condition:
    any of them
}