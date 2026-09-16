rule TTP_XOR_QUAD_CurrentVersionRun_467f {
  strings:
    $key_467f = { 15 10 [2] 31 1e [2] 1a 32 [2] 34 10 [2] 20 0b [2] 2f 11 [2] 31 0c [2] 33 0d [2] 28 0b [2] 34 0c [2] 28 23 }

  condition:
    any of them
}