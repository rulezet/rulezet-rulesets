rule TTP_XOR_QUAD_CurrentVersionRun_b722 {
  strings:
    $key_b722 = { e4 4d [2] c0 43 [2] eb 6f [2] c5 4d [2] d1 56 [2] de 4c [2] c0 51 [2] c2 50 [2] d9 56 [2] c5 51 [2] d9 7e }

  condition:
    any of them
}