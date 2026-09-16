rule TTP_XOR_MULT_DOSStub_729b {
  strings:
    $key_729b = { 26 f3 [2] 52 eb [2] 15 e9 [2] 52 f8 [2] 1c f4 [2] 10 fe [2] 07 f5 [2] 1c bb [2] 21 }

  condition:
    any of them
}