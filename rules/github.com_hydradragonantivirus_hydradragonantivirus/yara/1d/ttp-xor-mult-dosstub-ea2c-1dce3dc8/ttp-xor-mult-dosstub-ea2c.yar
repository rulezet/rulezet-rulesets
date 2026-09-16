rule TTP_XOR_MULT_DOSStub_ea2c {
  strings:
    $key_ea2c = { be 44 [2] ca 5c [2] 8d 5e [2] ca 4f [2] 84 43 [2] 88 49 [2] 9f 42 [2] 84 0c [2] b9 }

  condition:
    any of them
}