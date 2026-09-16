rule TTP_XOR_QUAD_CurrentVersionRun_ef58 {
  strings:
    $key_ef58 = { bc 37 [2] 98 39 [2] b3 15 [2] 9d 37 [2] 89 2c [2] 86 36 [2] 98 2b [2] 9a 2a [2] 81 2c [2] 9d 2b [2] 81 04 }

  condition:
    any of them
}