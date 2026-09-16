rule TTP_XOR_QUAD_CurrentVersionRun_ff09 {
  strings:
    $key_ff09 = { ac 66 [2] 88 68 [2] a3 44 [2] 8d 66 [2] 99 7d [2] 96 67 [2] 88 7a [2] 8a 7b [2] 91 7d [2] 8d 7a [2] 91 55 }

  condition:
    any of them
}