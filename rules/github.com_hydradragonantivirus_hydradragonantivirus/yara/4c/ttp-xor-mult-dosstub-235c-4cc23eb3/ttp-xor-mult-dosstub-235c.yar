rule TTP_XOR_MULT_DOSStub_235c {
  strings:
    $key_235c = { 77 34 [2] 03 2c [2] 44 2e [2] 03 3f [2] 4d 33 [2] 41 39 [2] 56 32 [2] 4d 7c [2] 70 }

  condition:
    any of them
}