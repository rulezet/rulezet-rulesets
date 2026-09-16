rule TTP_XOR_QUAD_CurrentVersionRun_25ee {
  strings:
    $key_25ee = { 76 81 [2] 52 8f [2] 79 a3 [2] 57 81 [2] 43 9a [2] 4c 80 [2] 52 9d [2] 50 9c [2] 4b 9a [2] 57 9d [2] 4b b2 }

  condition:
    any of them
}