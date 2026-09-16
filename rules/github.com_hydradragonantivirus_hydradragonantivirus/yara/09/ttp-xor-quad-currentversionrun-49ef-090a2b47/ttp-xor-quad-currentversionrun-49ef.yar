rule TTP_XOR_QUAD_CurrentVersionRun_49ef {
  strings:
    $key_49ef = { 1a 80 [2] 3e 8e [2] 15 a2 [2] 3b 80 [2] 2f 9b [2] 20 81 [2] 3e 9c [2] 3c 9d [2] 27 9b [2] 3b 9c [2] 27 b3 }

  condition:
    any of them
}