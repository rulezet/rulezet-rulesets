rule TTP_XOR_QUAD_CurrentVersionRun_ff15 {
  strings:
    $key_ff15 = { ac 7a [2] 88 74 [2] a3 58 [2] 8d 7a [2] 99 61 [2] 96 7b [2] 88 66 [2] 8a 67 [2] 91 61 [2] 8d 66 [2] 91 49 }

  condition:
    any of them
}