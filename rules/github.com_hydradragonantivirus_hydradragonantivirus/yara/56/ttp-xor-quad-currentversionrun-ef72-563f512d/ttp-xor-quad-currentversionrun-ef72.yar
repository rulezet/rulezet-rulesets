rule TTP_XOR_QUAD_CurrentVersionRun_ef72 {
  strings:
    $key_ef72 = { bc 1d [2] 98 13 [2] b3 3f [2] 9d 1d [2] 89 06 [2] 86 1c [2] 98 01 [2] 9a 00 [2] 81 06 [2] 9d 01 [2] 81 2e }

  condition:
    any of them
}