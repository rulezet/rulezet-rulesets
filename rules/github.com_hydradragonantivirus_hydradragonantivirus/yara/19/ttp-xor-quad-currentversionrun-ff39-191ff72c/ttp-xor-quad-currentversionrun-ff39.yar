rule TTP_XOR_QUAD_CurrentVersionRun_ff39 {
  strings:
    $key_ff39 = { ac 56 [2] 88 58 [2] a3 74 [2] 8d 56 [2] 99 4d [2] 96 57 [2] 88 4a [2] 8a 4b [2] 91 4d [2] 8d 4a [2] 91 65 }

  condition:
    any of them
}