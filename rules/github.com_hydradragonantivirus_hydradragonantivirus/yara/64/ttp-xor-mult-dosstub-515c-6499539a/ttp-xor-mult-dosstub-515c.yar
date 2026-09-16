rule TTP_XOR_MULT_DOSStub_515c {
  strings:
    $key_515c = { 05 34 [2] 71 2c [2] 36 2e [2] 71 3f [2] 3f 33 [2] 33 39 [2] 24 32 [2] 3f 7c [2] 02 }

  condition:
    any of them
}