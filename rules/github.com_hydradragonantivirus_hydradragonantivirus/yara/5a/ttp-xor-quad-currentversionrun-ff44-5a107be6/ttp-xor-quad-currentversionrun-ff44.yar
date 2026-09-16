rule TTP_XOR_QUAD_CurrentVersionRun_ff44 {
  strings:
    $key_ff44 = { ac 2b [2] 88 25 [2] a3 09 [2] 8d 2b [2] 99 30 [2] 96 2a [2] 88 37 [2] 8a 36 [2] 91 30 [2] 8d 37 [2] 91 18 }

  condition:
    any of them
}