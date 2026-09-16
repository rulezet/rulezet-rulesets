rule TTP_XOR_QUAD_CurrentVersionRun_57ee {
  strings:
    $key_57ee = { 04 81 [2] 20 8f [2] 0b a3 [2] 25 81 [2] 31 9a [2] 3e 80 [2] 20 9d [2] 22 9c [2] 39 9a [2] 25 9d [2] 39 b2 }

  condition:
    any of them
}