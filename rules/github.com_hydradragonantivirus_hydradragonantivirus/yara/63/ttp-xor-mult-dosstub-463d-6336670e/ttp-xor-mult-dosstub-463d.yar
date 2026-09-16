rule TTP_XOR_MULT_DOSStub_463d {
  strings:
    $key_463d = { 12 55 [2] 66 4d [2] 21 4f [2] 66 5e [2] 28 52 [2] 24 58 [2] 33 53 [2] 28 1d [2] 15 }

  condition:
    any of them
}