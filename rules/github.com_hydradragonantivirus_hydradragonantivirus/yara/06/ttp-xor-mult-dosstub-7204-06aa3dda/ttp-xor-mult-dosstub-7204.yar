rule TTP_XOR_MULT_DOSStub_7204 {
  strings:
    $key_7204 = { 26 6c [2] 52 74 [2] 15 76 [2] 52 67 [2] 1c 6b [2] 10 61 [2] 07 6a [2] 1c 24 [2] 21 }

  condition:
    any of them
}