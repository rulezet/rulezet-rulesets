rule TTP_XOR_QUAD_CurrentVersionRun_23ee {
  strings:
    $key_23ee = { 70 81 [2] 54 8f [2] 7f a3 [2] 51 81 [2] 45 9a [2] 4a 80 [2] 54 9d [2] 56 9c [2] 4d 9a [2] 51 9d [2] 4d b2 }

  condition:
    any of them
}