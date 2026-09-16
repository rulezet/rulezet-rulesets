rule TTP_XOR_MULT_DOSStub_345c {
  strings:
    $key_345c = { 60 34 [2] 14 2c [2] 53 2e [2] 14 3f [2] 5a 33 [2] 56 39 [2] 41 32 [2] 5a 7c [2] 67 }

  condition:
    any of them
}