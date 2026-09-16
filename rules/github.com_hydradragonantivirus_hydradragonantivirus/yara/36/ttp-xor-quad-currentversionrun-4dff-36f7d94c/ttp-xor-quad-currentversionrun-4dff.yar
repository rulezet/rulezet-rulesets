rule TTP_XOR_QUAD_CurrentVersionRun_4dff {
  strings:
    $key_4dff = { 1e 90 [2] 3a 9e [2] 11 b2 [2] 3f 90 [2] 2b 8b [2] 24 91 [2] 3a 8c [2] 38 8d [2] 23 8b [2] 3f 8c [2] 23 a3 }

  condition:
    any of them
}