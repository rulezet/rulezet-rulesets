rule TTP_XOR_QUAD_CurrentVersionRun_07ef {
  strings:
    $key_07ef = { 54 80 [2] 70 8e [2] 5b a2 [2] 75 80 [2] 61 9b [2] 6e 81 [2] 70 9c [2] 72 9d [2] 69 9b [2] 75 9c [2] 69 b3 }

  condition:
    any of them
}