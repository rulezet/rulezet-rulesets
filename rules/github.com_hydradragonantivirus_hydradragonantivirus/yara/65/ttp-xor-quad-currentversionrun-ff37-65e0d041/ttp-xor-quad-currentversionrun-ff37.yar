rule TTP_XOR_QUAD_CurrentVersionRun_ff37 {
  strings:
    $key_ff37 = { ac 58 [2] 88 56 [2] a3 7a [2] 8d 58 [2] 99 43 [2] 96 59 [2] 88 44 [2] 8a 45 [2] 91 43 [2] 8d 44 [2] 91 6b }

  condition:
    any of them
}