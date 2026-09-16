rule TTP_XOR_MULT_DOSStub_ea20 {
  strings:
    $key_ea20 = { be 48 [2] ca 50 [2] 8d 52 [2] ca 43 [2] 84 4f [2] 88 45 [2] 9f 4e [2] 84 00 [2] b9 }

  condition:
    any of them
}