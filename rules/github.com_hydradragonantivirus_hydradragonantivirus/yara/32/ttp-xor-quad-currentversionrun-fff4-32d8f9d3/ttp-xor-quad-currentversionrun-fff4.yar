rule TTP_XOR_QUAD_CurrentVersionRun_fff4 {
  strings:
    $key_fff4 = { ac 9b [2] 88 95 [2] a3 b9 [2] 8d 9b [2] 99 80 [2] 96 9a [2] 88 87 [2] 8a 86 [2] 91 80 [2] 8d 87 [2] 91 a8 }

  condition:
    any of them
}