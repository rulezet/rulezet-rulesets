rule TTP_XOR_QUAD_CurrentVersionRun_27ee {
  strings:
    $key_27ee = { 74 81 [2] 50 8f [2] 7b a3 [2] 55 81 [2] 41 9a [2] 4e 80 [2] 50 9d [2] 52 9c [2] 49 9a [2] 55 9d [2] 49 b2 }

  condition:
    any of them
}