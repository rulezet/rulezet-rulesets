rule TTP_XOR_QUAD_CurrentVersionRun_f4ee {
  strings:
    $key_f4ee = { a7 81 [2] 83 8f [2] a8 a3 [2] 86 81 [2] 92 9a [2] 9d 80 [2] 83 9d [2] 81 9c [2] 9a 9a [2] 86 9d [2] 9a b2 }

  condition:
    any of them
}