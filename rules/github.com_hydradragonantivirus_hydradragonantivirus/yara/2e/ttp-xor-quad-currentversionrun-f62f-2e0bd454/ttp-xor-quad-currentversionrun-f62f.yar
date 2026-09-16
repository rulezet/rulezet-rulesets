rule TTP_XOR_QUAD_CurrentVersionRun_f62f {
  strings:
    $key_f62f = { a5 40 [2] 81 4e [2] aa 62 [2] 84 40 [2] 90 5b [2] 9f 41 [2] 81 5c [2] 83 5d [2] 98 5b [2] 84 5c [2] 98 73 }

  condition:
    any of them
}