rule TTP_XOR_MULT_DOSStub_245c {
  strings:
    $key_245c = { 70 34 [2] 04 2c [2] 43 2e [2] 04 3f [2] 4a 33 [2] 46 39 [2] 51 32 [2] 4a 7c [2] 77 }

  condition:
    any of them
}