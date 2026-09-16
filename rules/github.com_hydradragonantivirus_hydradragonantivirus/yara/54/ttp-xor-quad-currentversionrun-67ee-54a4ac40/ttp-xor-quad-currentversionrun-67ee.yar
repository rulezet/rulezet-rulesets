rule TTP_XOR_QUAD_CurrentVersionRun_67ee {
  strings:
    $key_67ee = { 34 81 [2] 10 8f [2] 3b a3 [2] 15 81 [2] 01 9a [2] 0e 80 [2] 10 9d [2] 12 9c [2] 09 9a [2] 15 9d [2] 09 b2 }

  condition:
    any of them
}