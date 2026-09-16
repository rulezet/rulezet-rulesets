rule TTP_XOR_QUAD_CurrentVersionRun_29ef {
  strings:
    $key_29ef = { 7a 80 [2] 5e 8e [2] 75 a2 [2] 5b 80 [2] 4f 9b [2] 40 81 [2] 5e 9c [2] 5c 9d [2] 47 9b [2] 5b 9c [2] 47 b3 }

  condition:
    any of them
}