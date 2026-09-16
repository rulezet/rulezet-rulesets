rule TTP_XOR_MULT_DOSStub_ea5c {
  strings:
    $key_ea5c = { be 34 [2] ca 2c [2] 8d 2e [2] ca 3f [2] 84 33 [2] 88 39 [2] 9f 32 [2] 84 7c [2] b9 }

  condition:
    any of them
}