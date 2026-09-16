rule TTP_XOR_MULT_DOSStub_245a {
  strings:
    $key_245a = { 70 32 [2] 04 2a [2] 43 28 [2] 04 39 [2] 4a 35 [2] 46 3f [2] 51 34 [2] 4a 7a [2] 77 }

  condition:
    any of them
}