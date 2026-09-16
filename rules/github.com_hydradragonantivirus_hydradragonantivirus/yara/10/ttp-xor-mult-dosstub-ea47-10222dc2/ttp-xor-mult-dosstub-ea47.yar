rule TTP_XOR_MULT_DOSStub_ea47 {
  strings:
    $key_ea47 = { be 2f [2] ca 37 [2] 8d 35 [2] ca 24 [2] 84 28 [2] 88 22 [2] 9f 29 [2] 84 67 [2] b9 }

  condition:
    any of them
}