rule TTP_XOR_MULT_DOSStub_375c {
  strings:
    $key_375c = { 63 34 [2] 17 2c [2] 50 2e [2] 17 3f [2] 59 33 [2] 55 39 [2] 42 32 [2] 59 7c [2] 64 }

  condition:
    any of them
}