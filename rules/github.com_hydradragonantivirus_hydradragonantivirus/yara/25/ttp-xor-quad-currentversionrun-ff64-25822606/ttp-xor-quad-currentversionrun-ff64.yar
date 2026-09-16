rule TTP_XOR_QUAD_CurrentVersionRun_ff64 {
  strings:
    $key_ff64 = { ac 0b [2] 88 05 [2] a3 29 [2] 8d 0b [2] 99 10 [2] 96 0a [2] 88 17 [2] 8a 16 [2] 91 10 [2] 8d 17 [2] 91 38 }

  condition:
    any of them
}