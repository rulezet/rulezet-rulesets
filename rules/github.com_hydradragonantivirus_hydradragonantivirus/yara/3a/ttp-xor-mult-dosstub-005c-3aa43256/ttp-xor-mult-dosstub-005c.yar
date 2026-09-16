rule TTP_XOR_MULT_DOSStub_005c {
  strings:
    $key_005c = { 54 34 [2] 20 2c [2] 67 2e [2] 20 3f [2] 6e 33 [2] 62 39 [2] 75 32 [2] 6e 7c [2] 53 }

  condition:
    any of them
}