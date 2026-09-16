rule TTP_XOR_QUAD_CurrentVersionRun_ff63 {
  strings:
    $key_ff63 = { ac 0c [2] 88 02 [2] a3 2e [2] 8d 0c [2] 99 17 [2] 96 0d [2] 88 10 [2] 8a 11 [2] 91 17 [2] 8d 10 [2] 91 3f }

  condition:
    any of them
}