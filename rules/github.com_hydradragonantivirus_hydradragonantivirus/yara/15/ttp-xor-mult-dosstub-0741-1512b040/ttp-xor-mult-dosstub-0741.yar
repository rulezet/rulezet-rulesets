rule TTP_XOR_MULT_DOSStub_0741 {
  strings:
    $key_0741 = { 53 29 [2] 27 31 [2] 60 33 [2] 27 22 [2] 69 2e [2] 65 24 [2] 72 2f [2] 69 61 [2] 54 }

  condition:
    any of them
}