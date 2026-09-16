rule TTP_XOR_MULT_DOSStub_5f5c {
  strings:
    $key_5f5c = { 0b 34 [2] 7f 2c [2] 38 2e [2] 7f 3f [2] 31 33 [2] 3d 39 [2] 2a 32 [2] 31 7c [2] 0c }

  condition:
    any of them
}