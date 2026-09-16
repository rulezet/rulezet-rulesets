rule TTP_XOR_MULT_DOSStub_ea72 {
  strings:
    $key_ea72 = { be 1a [2] ca 02 [2] 8d 00 [2] ca 11 [2] 84 1d [2] 88 17 [2] 9f 1c [2] 84 52 [2] b9 }

  condition:
    any of them
}