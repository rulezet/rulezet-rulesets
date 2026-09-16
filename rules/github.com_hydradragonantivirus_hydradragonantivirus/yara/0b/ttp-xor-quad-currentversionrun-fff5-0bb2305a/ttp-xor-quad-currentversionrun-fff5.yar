rule TTP_XOR_QUAD_CurrentVersionRun_fff5 {
  strings:
    $key_fff5 = { ac 9a [2] 88 94 [2] a3 b8 [2] 8d 9a [2] 99 81 [2] 96 9b [2] 88 86 [2] 8a 87 [2] 91 81 [2] 8d 86 [2] 91 a9 }

  condition:
    any of them
}