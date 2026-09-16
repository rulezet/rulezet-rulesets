rule TTP_XOR_QUAD_CurrentVersionRun_f17f {
  strings:
    $key_f17f = { a2 10 [2] 86 1e [2] ad 32 [2] 83 10 [2] 97 0b [2] 98 11 [2] 86 0c [2] 84 0d [2] 9f 0b [2] 83 0c [2] 9f 23 }

  condition:
    any of them
}