rule TTP_XOR_QUAD_CurrentVersionRun_55ef {
  strings:
    $key_55ef = { 06 80 [2] 22 8e [2] 09 a2 [2] 27 80 [2] 33 9b [2] 3c 81 [2] 22 9c [2] 20 9d [2] 3b 9b [2] 27 9c [2] 3b b3 }

  condition:
    any of them
}