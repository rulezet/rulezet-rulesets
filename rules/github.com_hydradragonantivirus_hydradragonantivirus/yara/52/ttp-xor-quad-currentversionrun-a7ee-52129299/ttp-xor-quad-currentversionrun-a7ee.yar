rule TTP_XOR_QUAD_CurrentVersionRun_a7ee {
  strings:
    $key_a7ee = { f4 81 [2] d0 8f [2] fb a3 [2] d5 81 [2] c1 9a [2] ce 80 [2] d0 9d [2] d2 9c [2] c9 9a [2] d5 9d [2] c9 b2 }

  condition:
    any of them
}