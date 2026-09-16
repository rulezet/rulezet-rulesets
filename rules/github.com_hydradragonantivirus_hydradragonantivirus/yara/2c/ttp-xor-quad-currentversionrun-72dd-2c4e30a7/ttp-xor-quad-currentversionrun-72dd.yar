rule TTP_XOR_QUAD_CurrentVersionRun_72dd {
  strings:
    $key_72dd = { 21 b2 [2] 05 bc [2] 2e 90 [2] 00 b2 [2] 14 a9 [2] 1b b3 [2] 05 ae [2] 07 af [2] 1c a9 [2] 00 ae [2] 1c 81 }

  condition:
    any of them
}