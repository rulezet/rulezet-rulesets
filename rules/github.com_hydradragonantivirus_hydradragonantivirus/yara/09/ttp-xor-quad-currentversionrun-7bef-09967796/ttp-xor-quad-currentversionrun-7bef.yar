rule TTP_XOR_QUAD_CurrentVersionRun_7bef {
  strings:
    $key_7bef = { 28 80 [2] 0c 8e [2] 27 a2 [2] 09 80 [2] 1d 9b [2] 12 81 [2] 0c 9c [2] 0e 9d [2] 15 9b [2] 09 9c [2] 15 b3 }

  condition:
    any of them
}