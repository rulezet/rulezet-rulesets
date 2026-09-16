rule TTP_XOR_MULT_DOSStub_0f5c {
  strings:
    $key_0f5c = { 5b 34 [2] 2f 2c [2] 68 2e [2] 2f 3f [2] 61 33 [2] 6d 39 [2] 7a 32 [2] 61 7c [2] 5c }

  condition:
    any of them
}