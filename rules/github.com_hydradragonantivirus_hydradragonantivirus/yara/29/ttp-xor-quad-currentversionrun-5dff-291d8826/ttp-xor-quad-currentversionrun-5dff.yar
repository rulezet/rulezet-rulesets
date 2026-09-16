rule TTP_XOR_QUAD_CurrentVersionRun_5dff {
  strings:
    $key_5dff = { 0e 90 [2] 2a 9e [2] 01 b2 [2] 2f 90 [2] 3b 8b [2] 34 91 [2] 2a 8c [2] 28 8d [2] 33 8b [2] 2f 8c [2] 33 a3 }

  condition:
    any of them
}