rule TTP_XOR_QUAD_CurrentVersionRun_ff59 {
  strings:
    $key_ff59 = { ac 36 [2] 88 38 [2] a3 14 [2] 8d 36 [2] 99 2d [2] 96 37 [2] 88 2a [2] 8a 2b [2] 91 2d [2] 8d 2a [2] 91 05 }

  condition:
    any of them
}