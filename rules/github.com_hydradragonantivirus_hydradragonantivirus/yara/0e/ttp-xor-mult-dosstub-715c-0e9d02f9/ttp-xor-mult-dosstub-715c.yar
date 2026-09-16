rule TTP_XOR_MULT_DOSStub_715c {
  strings:
    $key_715c = { 25 34 [2] 51 2c [2] 16 2e [2] 51 3f [2] 1f 33 [2] 13 39 [2] 04 32 [2] 1f 7c [2] 22 }

  condition:
    any of them
}