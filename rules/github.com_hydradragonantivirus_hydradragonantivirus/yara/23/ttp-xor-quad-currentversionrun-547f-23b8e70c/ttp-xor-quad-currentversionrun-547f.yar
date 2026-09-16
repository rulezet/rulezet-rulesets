rule TTP_XOR_QUAD_CurrentVersionRun_547f {
  strings:
    $key_547f = { 07 10 [2] 23 1e [2] 08 32 [2] 26 10 [2] 32 0b [2] 3d 11 [2] 23 0c [2] 21 0d [2] 3a 0b [2] 26 0c [2] 3a 23 }

  condition:
    any of them
}