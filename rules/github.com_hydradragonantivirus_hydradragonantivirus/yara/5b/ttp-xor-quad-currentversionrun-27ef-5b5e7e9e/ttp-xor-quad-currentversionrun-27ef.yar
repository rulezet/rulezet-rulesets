rule TTP_XOR_QUAD_CurrentVersionRun_27ef {
  strings:
    $key_27ef = { 74 80 [2] 50 8e [2] 7b a2 [2] 55 80 [2] 41 9b [2] 4e 81 [2] 50 9c [2] 52 9d [2] 49 9b [2] 55 9c [2] 49 b3 }

  condition:
    any of them
}