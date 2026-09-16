rule TTP_XOR_MULT_DOSStub_285c {
  strings:
    $key_285c = { 7c 34 [2] 08 2c [2] 4f 2e [2] 08 3f [2] 46 33 [2] 4a 39 [2] 5d 32 [2] 46 7c [2] 7b }

  condition:
    any of them
}