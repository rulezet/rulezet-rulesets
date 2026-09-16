rule TTP_XOR_QUAD_CurrentVersionRun_ff8a {
  strings:
    $key_ff8a = { ac e5 [2] 88 eb [2] a3 c7 [2] 8d e5 [2] 99 fe [2] 96 e4 [2] 88 f9 [2] 8a f8 [2] 91 fe [2] 8d f9 [2] 91 d6 }

  condition:
    any of them
}