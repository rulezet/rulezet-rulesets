rule TTP_XOR_MULT_DOSStub_785c {
  strings:
    $key_785c = { 2c 34 [2] 58 2c [2] 1f 2e [2] 58 3f [2] 16 33 [2] 1a 39 [2] 0d 32 [2] 16 7c [2] 2b }

  condition:
    any of them
}