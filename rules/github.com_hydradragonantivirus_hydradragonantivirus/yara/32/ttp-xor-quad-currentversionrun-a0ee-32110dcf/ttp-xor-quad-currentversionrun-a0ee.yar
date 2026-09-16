rule TTP_XOR_QUAD_CurrentVersionRun_a0ee {
  strings:
    $key_a0ee = { f3 81 [2] d7 8f [2] fc a3 [2] d2 81 [2] c6 9a [2] c9 80 [2] d7 9d [2] d5 9c [2] ce 9a [2] d2 9d [2] ce b2 }

  condition:
    any of them
}