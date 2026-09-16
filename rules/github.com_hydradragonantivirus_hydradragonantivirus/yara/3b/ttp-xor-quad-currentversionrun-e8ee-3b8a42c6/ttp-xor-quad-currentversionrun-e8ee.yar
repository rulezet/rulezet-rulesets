rule TTP_XOR_QUAD_CurrentVersionRun_e8ee {
  strings:
    $key_e8ee = { bb 81 [2] 9f 8f [2] b4 a3 [2] 9a 81 [2] 8e 9a [2] 81 80 [2] 9f 9d [2] 9d 9c [2] 86 9a [2] 9a 9d [2] 86 b2 }

  condition:
    any of them
}