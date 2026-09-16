rule TTP_XOR_MULT_DOSStub_0e40 {
  strings:
    $key_0e40 = { 5a 28 [2] 2e 30 [2] 69 32 [2] 2e 23 [2] 60 2f [2] 6c 25 [2] 7b 2e [2] 60 60 [2] 5d }

  condition:
    any of them
}