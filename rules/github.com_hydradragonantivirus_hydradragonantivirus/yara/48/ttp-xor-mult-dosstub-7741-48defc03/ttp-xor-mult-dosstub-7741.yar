rule TTP_XOR_MULT_DOSStub_7741 {
  strings:
    $key_7741 = { 23 29 [2] 57 31 [2] 10 33 [2] 57 22 [2] 19 2e [2] 15 24 [2] 02 2f [2] 19 61 [2] 24 }

  condition:
    any of them
}