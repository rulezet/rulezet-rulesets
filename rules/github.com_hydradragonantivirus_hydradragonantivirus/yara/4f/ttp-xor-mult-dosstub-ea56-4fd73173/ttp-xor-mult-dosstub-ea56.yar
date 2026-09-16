rule TTP_XOR_MULT_DOSStub_ea56 {
  strings:
    $key_ea56 = { be 3e [2] ca 26 [2] 8d 24 [2] ca 35 [2] 84 39 [2] 88 33 [2] 9f 38 [2] 84 76 [2] b9 }

  condition:
    any of them
}