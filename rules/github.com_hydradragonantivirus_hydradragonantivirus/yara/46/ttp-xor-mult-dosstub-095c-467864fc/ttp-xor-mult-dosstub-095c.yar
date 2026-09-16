rule TTP_XOR_MULT_DOSStub_095c {
  strings:
    $key_095c = { 5d 34 [2] 29 2c [2] 6e 2e [2] 29 3f [2] 67 33 [2] 6b 39 [2] 7c 32 [2] 67 7c [2] 5a }

  condition:
    any of them
}