rule TTP_XOR_QUAD_CurrentVersionRun_437f {
  strings:
    $key_437f = { 10 10 [2] 34 1e [2] 1f 32 [2] 31 10 [2] 25 0b [2] 2a 11 [2] 34 0c [2] 36 0d [2] 2d 0b [2] 31 0c [2] 2d 23 }

  condition:
    any of them
}