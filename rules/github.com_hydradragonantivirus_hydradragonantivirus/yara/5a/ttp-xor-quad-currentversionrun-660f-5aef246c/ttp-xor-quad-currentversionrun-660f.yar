rule TTP_XOR_QUAD_CurrentVersionRun_660f {
  strings:
    $key_660f = { 35 60 [2] 11 6e [2] 3a 42 [2] 14 60 [2] 00 7b [2] 0f 61 [2] 11 7c [2] 13 7d [2] 08 7b [2] 14 7c [2] 08 53 }

  condition:
    any of them
}