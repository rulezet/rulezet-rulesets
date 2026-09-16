rule TTP_XOR_QUAD_CurrentVersionRun_ff57 {
  strings:
    $key_ff57 = { ac 38 [2] 88 36 [2] a3 1a [2] 8d 38 [2] 99 23 [2] 96 39 [2] 88 24 [2] 8a 25 [2] 91 23 [2] 8d 24 [2] 91 0b }

  condition:
    any of them
}