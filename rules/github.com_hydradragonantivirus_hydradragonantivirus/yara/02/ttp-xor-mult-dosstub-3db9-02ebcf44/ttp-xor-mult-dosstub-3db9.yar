rule TTP_XOR_MULT_DOSStub_3db9 {
  strings:
    $key_3db9 = { 69 d1 [2] 1d c9 [2] 5a cb [2] 1d da [2] 53 d6 [2] 5f dc [2] 48 d7 [2] 53 99 [2] 6e }

  condition:
    any of them
}