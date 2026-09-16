rule TTP_XOR_QUAD_CurrentVersionRun_657f {
  strings:
    $key_657f = { 36 10 [2] 12 1e [2] 39 32 [2] 17 10 [2] 03 0b [2] 0c 11 [2] 12 0c [2] 10 0d [2] 0b 0b [2] 17 0c [2] 0b 23 }

  condition:
    any of them
}