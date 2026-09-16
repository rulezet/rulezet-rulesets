rule TTP_XOR_QUAD_CurrentVersionRun_1458 {
  strings:
    $key_1458 = { 47 37 [2] 63 39 [2] 48 15 [2] 66 37 [2] 72 2c [2] 7d 36 [2] 63 2b [2] 61 2a [2] 7a 2c [2] 66 2b [2] 7a 04 }

  condition:
    any of them
}