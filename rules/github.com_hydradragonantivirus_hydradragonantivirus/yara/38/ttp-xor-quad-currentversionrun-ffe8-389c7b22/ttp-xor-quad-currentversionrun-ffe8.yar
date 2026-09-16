rule TTP_XOR_QUAD_CurrentVersionRun_ffe8 {
  strings:
    $key_ffe8 = { ac 87 [2] 88 89 [2] a3 a5 [2] 8d 87 [2] 99 9c [2] 96 86 [2] 88 9b [2] 8a 9a [2] 91 9c [2] 8d 9b [2] 91 b4 }

  condition:
    any of them
}