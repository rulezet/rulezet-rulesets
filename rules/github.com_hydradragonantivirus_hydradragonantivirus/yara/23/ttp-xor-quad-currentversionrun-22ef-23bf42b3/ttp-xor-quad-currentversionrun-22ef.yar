rule TTP_XOR_QUAD_CurrentVersionRun_22ef {
  strings:
    $key_22ef = { 71 80 [2] 55 8e [2] 7e a2 [2] 50 80 [2] 44 9b [2] 4b 81 [2] 55 9c [2] 57 9d [2] 4c 9b [2] 50 9c [2] 4c b3 }

  condition:
    any of them
}