rule TTP_XOR_QUAD_CurrentVersionRun_5cff {
  strings:
    $key_5cff = { 0f 90 [2] 2b 9e [2] 00 b2 [2] 2e 90 [2] 3a 8b [2] 35 91 [2] 2b 8c [2] 29 8d [2] 32 8b [2] 2e 8c [2] 32 a3 }

  condition:
    any of them
}