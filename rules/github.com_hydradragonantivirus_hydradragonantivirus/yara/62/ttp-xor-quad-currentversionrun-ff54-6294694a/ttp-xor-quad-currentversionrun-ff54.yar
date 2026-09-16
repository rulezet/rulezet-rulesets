rule TTP_XOR_QUAD_CurrentVersionRun_ff54 {
  strings:
    $key_ff54 = { ac 3b [2] 88 35 [2] a3 19 [2] 8d 3b [2] 99 20 [2] 96 3a [2] 88 27 [2] 8a 26 [2] 91 20 [2] 8d 27 [2] 91 08 }

  condition:
    any of them
}