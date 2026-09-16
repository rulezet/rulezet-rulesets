rule TTP_XOR_QUAD_CurrentVersionRun_ffe5 {
  strings:
    $key_ffe5 = { ac 8a [2] 88 84 [2] a3 a8 [2] 8d 8a [2] 99 91 [2] 96 8b [2] 88 96 [2] 8a 97 [2] 91 91 [2] 8d 96 [2] 91 b9 }

  condition:
    any of them
}