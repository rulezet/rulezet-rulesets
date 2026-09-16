rule TTP_XOR_QUAD_CurrentVersionRun_ff68 {
  strings:
    $key_ff68 = { ac 07 [2] 88 09 [2] a3 25 [2] 8d 07 [2] 99 1c [2] 96 06 [2] 88 1b [2] 8a 1a [2] 91 1c [2] 8d 1b [2] 91 34 }

  condition:
    any of them
}