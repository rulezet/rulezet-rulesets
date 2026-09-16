rule TTP_XOR_QUAD_CurrentVersionRun_ff56 {
  strings:
    $key_ff56 = { ac 39 [2] 88 37 [2] a3 1b [2] 8d 39 [2] 99 22 [2] 96 38 [2] 88 25 [2] 8a 24 [2] 91 22 [2] 8d 25 [2] 91 0a }

  condition:
    any of them
}