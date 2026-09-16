rule TTP_XOR_MULT_DOSStub_461a {
  strings:
    $key_461a = { 12 72 [2] 66 6a [2] 21 68 [2] 66 79 [2] 28 75 [2] 24 7f [2] 33 74 [2] 28 3a [2] 15 }

  condition:
    any of them
}