rule TTP_XOR_QUAD_CurrentVersionRun_ff04 {
  strings:
    $key_ff04 = { ac 6b [2] 88 65 [2] a3 49 [2] 8d 6b [2] 99 70 [2] 96 6a [2] 88 77 [2] 8a 76 [2] 91 70 [2] 8d 77 [2] 91 58 }

  condition:
    any of them
}