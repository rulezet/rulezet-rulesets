rule TTP_XOR_MULT_DOSStub_ea70 {
  strings:
    $key_ea70 = { be 18 [2] ca 00 [2] 8d 02 [2] ca 13 [2] 84 1f [2] 88 15 [2] 9f 1e [2] 84 50 [2] b9 }

  condition:
    any of them
}