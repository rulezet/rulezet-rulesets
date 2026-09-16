rule TTP_XOR_QUAD_CurrentVersionRun_76ef {
  strings:
    $key_76ef = { 25 80 [2] 01 8e [2] 2a a2 [2] 04 80 [2] 10 9b [2] 1f 81 [2] 01 9c [2] 03 9d [2] 18 9b [2] 04 9c [2] 18 b3 }

  condition:
    any of them
}