rule TTP_XOR_QUAD_CurrentVersionRun_ff18 {
  strings:
    $key_ff18 = { ac 77 [2] 88 79 [2] a3 55 [2] 8d 77 [2] 99 6c [2] 96 76 [2] 88 6b [2] 8a 6a [2] 91 6c [2] 8d 6b [2] 91 44 }

  condition:
    any of them
}