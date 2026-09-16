rule TTP_XOR_MULT_DOSStub_455c {
  strings:
    $key_455c = { 11 34 [2] 65 2c [2] 22 2e [2] 65 3f [2] 2b 33 [2] 27 39 [2] 30 32 [2] 2b 7c [2] 16 }

  condition:
    any of them
}