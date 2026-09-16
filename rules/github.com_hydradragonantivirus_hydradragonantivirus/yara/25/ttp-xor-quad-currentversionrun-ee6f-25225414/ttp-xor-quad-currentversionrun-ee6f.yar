rule TTP_XOR_QUAD_CurrentVersionRun_ee6f {
  strings:
    $key_ee6f = { bd 00 [2] 99 0e [2] b2 22 [2] 9c 00 [2] 88 1b [2] 87 01 [2] 99 1c [2] 9b 1d [2] 80 1b [2] 9c 1c [2] 80 33 }

  condition:
    any of them
}