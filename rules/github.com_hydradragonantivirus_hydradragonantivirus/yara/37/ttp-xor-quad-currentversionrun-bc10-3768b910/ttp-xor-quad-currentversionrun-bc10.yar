rule TTP_XOR_QUAD_CurrentVersionRun_bc10 {
  strings:
    $key_bc10 = { ef 7f [2] cb 71 [2] e0 5d [2] ce 7f [2] da 64 [2] d5 7e [2] cb 63 [2] c9 62 [2] d2 64 [2] ce 63 [2] d2 4c }

  condition:
    any of them
}