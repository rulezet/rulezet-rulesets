rule TTP_XOR_QUAD_CurrentVersionRun_79ef {
  strings:
    $key_79ef = { 2a 80 [2] 0e 8e [2] 25 a2 [2] 0b 80 [2] 1f 9b [2] 10 81 [2] 0e 9c [2] 0c 9d [2] 17 9b [2] 0b 9c [2] 17 b3 }

  condition:
    any of them
}