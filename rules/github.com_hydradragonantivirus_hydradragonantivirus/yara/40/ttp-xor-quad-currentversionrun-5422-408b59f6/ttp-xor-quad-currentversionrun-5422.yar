rule TTP_XOR_QUAD_CurrentVersionRun_5422 {
  strings:
    $key_5422 = { 07 4d [2] 23 43 [2] 08 6f [2] 26 4d [2] 32 56 [2] 3d 4c [2] 23 51 [2] 21 50 [2] 3a 56 [2] 26 51 [2] 3a 7e }

  condition:
    any of them
}