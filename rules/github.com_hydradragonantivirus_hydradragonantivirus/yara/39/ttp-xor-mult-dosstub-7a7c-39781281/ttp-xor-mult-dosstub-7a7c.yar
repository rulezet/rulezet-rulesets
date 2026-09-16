rule TTP_XOR_MULT_DOSStub_7a7c {
  strings:
    $key_7a7c = { 2e 14 [2] 5a 0c [2] 1d 0e [2] 5a 1f [2] 14 13 [2] 18 19 [2] 0f 12 [2] 14 5c [2] 29 }

  condition:
    any of them
}