rule TTP_XOR_QUAD_CurrentVersionRun_36ee {
  strings:
    $key_36ee = { 65 81 [2] 41 8f [2] 6a a3 [2] 44 81 [2] 50 9a [2] 5f 80 [2] 41 9d [2] 43 9c [2] 58 9a [2] 44 9d [2] 58 b2 }

  condition:
    any of them
}