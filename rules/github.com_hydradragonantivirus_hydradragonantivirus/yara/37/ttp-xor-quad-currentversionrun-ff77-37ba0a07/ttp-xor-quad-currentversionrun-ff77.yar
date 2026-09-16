rule TTP_XOR_QUAD_CurrentVersionRun_ff77 {
  strings:
    $key_ff77 = { ac 18 [2] 88 16 [2] a3 3a [2] 8d 18 [2] 99 03 [2] 96 19 [2] 88 04 [2] 8a 05 [2] 91 03 [2] 8d 04 [2] 91 2b }

  condition:
    any of them
}