rule TTP_XOR_QUAD_CurrentVersionRun_ff25 {
  strings:
    $key_ff25 = { ac 4a [2] 88 44 [2] a3 68 [2] 8d 4a [2] 99 51 [2] 96 4b [2] 88 56 [2] 8a 57 [2] 91 51 [2] 8d 56 [2] 91 79 }

  condition:
    any of them
}