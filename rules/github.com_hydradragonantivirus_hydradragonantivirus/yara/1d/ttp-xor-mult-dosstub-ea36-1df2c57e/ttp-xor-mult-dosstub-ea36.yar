rule TTP_XOR_MULT_DOSStub_ea36 {
  strings:
    $key_ea36 = { be 5e [2] ca 46 [2] 8d 44 [2] ca 55 [2] 84 59 [2] 88 53 [2] 9f 58 [2] 84 16 [2] b9 }

  condition:
    any of them
}