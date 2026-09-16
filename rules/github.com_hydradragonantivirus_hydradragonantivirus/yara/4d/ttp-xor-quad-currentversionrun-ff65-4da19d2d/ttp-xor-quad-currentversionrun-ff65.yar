rule TTP_XOR_QUAD_CurrentVersionRun_ff65 {
  strings:
    $key_ff65 = { ac 0a [2] 88 04 [2] a3 28 [2] 8d 0a [2] 99 11 [2] 96 0b [2] 88 16 [2] 8a 17 [2] 91 11 [2] 8d 16 [2] 91 39 }

  condition:
    any of them
}