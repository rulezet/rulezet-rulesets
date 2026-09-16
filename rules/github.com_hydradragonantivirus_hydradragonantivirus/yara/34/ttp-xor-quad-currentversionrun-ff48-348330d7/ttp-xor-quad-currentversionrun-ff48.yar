rule TTP_XOR_QUAD_CurrentVersionRun_ff48 {
  strings:
    $key_ff48 = { ac 27 [2] 88 29 [2] a3 05 [2] 8d 27 [2] 99 3c [2] 96 26 [2] 88 3b [2] 8a 3a [2] 91 3c [2] 8d 3b [2] 91 14 }

  condition:
    any of them
}