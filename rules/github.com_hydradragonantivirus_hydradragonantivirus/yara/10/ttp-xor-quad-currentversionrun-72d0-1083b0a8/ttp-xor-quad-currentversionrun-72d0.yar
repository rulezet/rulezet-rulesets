rule TTP_XOR_QUAD_CurrentVersionRun_72d0 {
  strings:
    $key_72d0 = { 21 bf [2] 05 b1 [2] 2e 9d [2] 00 bf [2] 14 a4 [2] 1b be [2] 05 a3 [2] 07 a2 [2] 1c a4 [2] 00 a3 [2] 1c 8c }

  condition:
    any of them
}