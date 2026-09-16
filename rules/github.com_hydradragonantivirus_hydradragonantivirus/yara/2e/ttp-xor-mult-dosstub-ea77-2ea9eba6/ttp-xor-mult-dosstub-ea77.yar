rule TTP_XOR_MULT_DOSStub_ea77 {
  strings:
    $key_ea77 = { be 1f [2] ca 07 [2] 8d 05 [2] ca 14 [2] 84 18 [2] 88 12 [2] 9f 19 [2] 84 57 [2] b9 }

  condition:
    any of them
}