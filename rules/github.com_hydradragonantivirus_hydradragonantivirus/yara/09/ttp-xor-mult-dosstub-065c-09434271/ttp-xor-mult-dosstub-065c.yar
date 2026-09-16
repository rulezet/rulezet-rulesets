rule TTP_XOR_MULT_DOSStub_065c {
  strings:
    $key_065c = { 52 34 [2] 26 2c [2] 61 2e [2] 26 3f [2] 68 33 [2] 64 39 [2] 73 32 [2] 68 7c [2] 55 }

  condition:
    any of them
}