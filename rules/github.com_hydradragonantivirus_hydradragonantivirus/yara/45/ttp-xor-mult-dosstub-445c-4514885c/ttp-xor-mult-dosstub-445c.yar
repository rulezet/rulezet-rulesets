rule TTP_XOR_MULT_DOSStub_445c {
  strings:
    $key_445c = { 10 34 [2] 64 2c [2] 23 2e [2] 64 3f [2] 2a 33 [2] 26 39 [2] 31 32 [2] 2a 7c [2] 17 }

  condition:
    any of them
}