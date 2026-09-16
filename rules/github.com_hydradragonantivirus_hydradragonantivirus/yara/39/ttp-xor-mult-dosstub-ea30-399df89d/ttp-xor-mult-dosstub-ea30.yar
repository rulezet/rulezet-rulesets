rule TTP_XOR_MULT_DOSStub_ea30 {
  strings:
    $key_ea30 = { be 58 [2] ca 40 [2] 8d 42 [2] ca 53 [2] 84 5f [2] 88 55 [2] 9f 5e [2] 84 10 [2] b9 }

  condition:
    any of them
}