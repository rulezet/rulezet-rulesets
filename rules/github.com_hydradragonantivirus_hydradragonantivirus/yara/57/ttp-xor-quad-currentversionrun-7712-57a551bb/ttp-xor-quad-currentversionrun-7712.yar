rule TTP_XOR_QUAD_CurrentVersionRun_7712 {
  strings:
    $key_7712 = { 24 7d [2] 00 73 [2] 2b 5f [2] 05 7d [2] 11 66 [2] 1e 7c [2] 00 61 [2] 02 60 [2] 19 66 [2] 05 61 [2] 19 4e }

  condition:
    any of them
}