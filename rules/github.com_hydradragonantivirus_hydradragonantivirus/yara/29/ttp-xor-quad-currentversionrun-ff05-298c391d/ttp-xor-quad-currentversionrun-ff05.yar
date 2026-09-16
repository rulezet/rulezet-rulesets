rule TTP_XOR_QUAD_CurrentVersionRun_ff05 {
  strings:
    $key_ff05 = { ac 6a [2] 88 64 [2] a3 48 [2] 8d 6a [2] 99 71 [2] 96 6b [2] 88 76 [2] 8a 77 [2] 91 71 [2] 8d 76 [2] 91 59 }

  condition:
    any of them
}