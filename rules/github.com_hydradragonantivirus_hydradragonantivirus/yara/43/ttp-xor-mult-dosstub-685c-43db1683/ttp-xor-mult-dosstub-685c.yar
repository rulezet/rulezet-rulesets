rule TTP_XOR_MULT_DOSStub_685c {
  strings:
    $key_685c = { 3c 34 [2] 48 2c [2] 0f 2e [2] 48 3f [2] 06 33 [2] 0a 39 [2] 1d 32 [2] 06 7c [2] 3b }

  condition:
    any of them
}