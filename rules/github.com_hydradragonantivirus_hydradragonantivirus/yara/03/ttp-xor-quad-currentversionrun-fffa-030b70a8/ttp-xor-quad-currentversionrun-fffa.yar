rule TTP_XOR_QUAD_CurrentVersionRun_fffa {
  strings:
    $key_fffa = { ac 95 [2] 88 9b [2] a3 b7 [2] 8d 95 [2] 99 8e [2] 96 94 [2] 88 89 [2] 8a 88 [2] 91 8e [2] 8d 89 [2] 91 a6 }

  condition:
    any of them
}