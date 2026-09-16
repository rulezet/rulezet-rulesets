rule TTP_XOR_QUAD_CurrentVersionRun_f67f {
  strings:
    $key_f67f = { a5 10 [2] 81 1e [2] aa 32 [2] 84 10 [2] 90 0b [2] 9f 11 [2] 81 0c [2] 83 0d [2] 98 0b [2] 84 0c [2] 98 23 }

  condition:
    any of them
}