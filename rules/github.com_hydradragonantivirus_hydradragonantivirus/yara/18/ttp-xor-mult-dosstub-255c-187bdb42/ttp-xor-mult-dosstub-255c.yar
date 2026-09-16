rule TTP_XOR_MULT_DOSStub_255c {
  strings:
    $key_255c = { 71 34 [2] 05 2c [2] 42 2e [2] 05 3f [2] 4b 33 [2] 47 39 [2] 50 32 [2] 4b 7c [2] 76 }

  condition:
    any of them
}