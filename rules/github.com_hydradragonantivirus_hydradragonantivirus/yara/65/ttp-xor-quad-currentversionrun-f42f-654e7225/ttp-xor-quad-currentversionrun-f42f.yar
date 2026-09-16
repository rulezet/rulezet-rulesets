rule TTP_XOR_QUAD_CurrentVersionRun_f42f {
  strings:
    $key_f42f = { a7 40 [2] 83 4e [2] a8 62 [2] 86 40 [2] 92 5b [2] 9d 41 [2] 83 5c [2] 81 5d [2] 9a 5b [2] 86 5c [2] 9a 73 }

  condition:
    any of them
}