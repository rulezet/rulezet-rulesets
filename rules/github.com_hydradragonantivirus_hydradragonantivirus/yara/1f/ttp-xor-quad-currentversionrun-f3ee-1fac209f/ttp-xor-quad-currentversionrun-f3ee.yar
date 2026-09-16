rule TTP_XOR_QUAD_CurrentVersionRun_f3ee {
  strings:
    $key_f3ee = { a0 81 [2] 84 8f [2] af a3 [2] 81 81 [2] 95 9a [2] 9a 80 [2] 84 9d [2] 86 9c [2] 9d 9a [2] 81 9d [2] 9d b2 }

  condition:
    any of them
}