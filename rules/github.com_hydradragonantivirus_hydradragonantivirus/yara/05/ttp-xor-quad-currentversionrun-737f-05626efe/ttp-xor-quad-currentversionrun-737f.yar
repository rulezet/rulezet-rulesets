rule TTP_XOR_QUAD_CurrentVersionRun_737f {
  strings:
    $key_737f = { 20 10 [2] 04 1e [2] 2f 32 [2] 01 10 [2] 15 0b [2] 1a 11 [2] 04 0c [2] 06 0d [2] 1d 0b [2] 01 0c [2] 1d 23 }

  condition:
    any of them
}