rule TTP_XOR_QUAD_CurrentVersionRun_4cff {
  strings:
    $key_4cff = { 1f 90 [2] 3b 9e [2] 10 b2 [2] 3e 90 [2] 2a 8b [2] 25 91 [2] 3b 8c [2] 39 8d [2] 22 8b [2] 3e 8c [2] 22 a3 }

  condition:
    any of them
}