rule TTP_XOR_QUAD_CurrentVersionRun_4e7f {
  strings:
    $key_4e7f = { 1d 10 [2] 39 1e [2] 12 32 [2] 3c 10 [2] 28 0b [2] 27 11 [2] 39 0c [2] 3b 0d [2] 20 0b [2] 3c 0c [2] 20 23 }

  condition:
    any of them
}