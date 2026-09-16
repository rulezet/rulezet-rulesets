rule TTP_XOR_QUAD_CurrentVersionRun_bc22 {
  strings:
    $key_bc22 = { ef 4d [2] cb 43 [2] e0 6f [2] ce 4d [2] da 56 [2] d5 4c [2] cb 51 [2] c9 50 [2] d2 56 [2] ce 51 [2] d2 7e }

  condition:
    any of them
}