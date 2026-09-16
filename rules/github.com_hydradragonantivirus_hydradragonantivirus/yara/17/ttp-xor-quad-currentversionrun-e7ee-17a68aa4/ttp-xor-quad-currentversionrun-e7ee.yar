rule TTP_XOR_QUAD_CurrentVersionRun_e7ee {
  strings:
    $key_e7ee = { b4 81 [2] 90 8f [2] bb a3 [2] 95 81 [2] 81 9a [2] 8e 80 [2] 90 9d [2] 92 9c [2] 89 9a [2] 95 9d [2] 89 b2 }

  condition:
    any of them
}