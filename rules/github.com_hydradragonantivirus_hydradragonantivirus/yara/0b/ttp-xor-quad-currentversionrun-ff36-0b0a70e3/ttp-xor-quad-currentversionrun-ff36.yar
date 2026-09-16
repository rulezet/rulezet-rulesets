rule TTP_XOR_QUAD_CurrentVersionRun_ff36 {
  strings:
    $key_ff36 = { ac 59 [2] 88 57 [2] a3 7b [2] 8d 59 [2] 99 42 [2] 96 58 [2] 88 45 [2] 8a 44 [2] 91 42 [2] 8d 45 [2] 91 6a }

  condition:
    any of them
}