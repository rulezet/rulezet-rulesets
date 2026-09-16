rule TTP_XOR_MULT_DOSStub_ea46 {
  strings:
    $key_ea46 = { be 2e [2] ca 36 [2] 8d 34 [2] ca 25 [2] 84 29 [2] 88 23 [2] 9f 28 [2] 84 66 [2] b9 }

  condition:
    any of them
}