rule TTP_XOR_QUAD_CurrentVersionRun_6cff {
  strings:
    $key_6cff = { 3f 90 [2] 1b 9e [2] 30 b2 [2] 1e 90 [2] 0a 8b [2] 05 91 [2] 1b 8c [2] 19 8d [2] 02 8b [2] 1e 8c [2] 02 a3 }

  condition:
    any of them
}