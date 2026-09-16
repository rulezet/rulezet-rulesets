rule TTP_XOR_MULT_DOSStub_e35c {
  strings:
    $key_e35c = { b7 34 [2] c3 2c [2] 84 2e [2] c3 3f [2] 8d 33 [2] 81 39 [2] 96 32 [2] 8d 7c [2] b0 }

  condition:
    any of them
}