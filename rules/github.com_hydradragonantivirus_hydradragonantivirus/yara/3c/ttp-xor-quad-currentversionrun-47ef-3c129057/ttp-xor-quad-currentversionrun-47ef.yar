rule TTP_XOR_QUAD_CurrentVersionRun_47ef {
  strings:
    $key_47ef = { 14 80 [2] 30 8e [2] 1b a2 [2] 35 80 [2] 21 9b [2] 2e 81 [2] 30 9c [2] 32 9d [2] 29 9b [2] 35 9c [2] 29 b3 }

  condition:
    any of them
}