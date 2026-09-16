rule TTP_XOR_QUAD_CurrentVersionRun_ff34 {
  strings:
    $key_ff34 = { ac 5b [2] 88 55 [2] a3 79 [2] 8d 5b [2] 99 40 [2] 96 5a [2] 88 47 [2] 8a 46 [2] 91 40 [2] 8d 47 [2] 91 68 }

  condition:
    any of them
}