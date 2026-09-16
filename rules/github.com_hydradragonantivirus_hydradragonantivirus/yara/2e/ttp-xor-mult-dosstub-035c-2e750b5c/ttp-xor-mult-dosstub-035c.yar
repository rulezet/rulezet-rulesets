rule TTP_XOR_MULT_DOSStub_035c {
  strings:
    $key_035c = { 57 34 [2] 23 2c [2] 64 2e [2] 23 3f [2] 6d 33 [2] 61 39 [2] 76 32 [2] 6d 7c [2] 50 }

  condition:
    any of them
}