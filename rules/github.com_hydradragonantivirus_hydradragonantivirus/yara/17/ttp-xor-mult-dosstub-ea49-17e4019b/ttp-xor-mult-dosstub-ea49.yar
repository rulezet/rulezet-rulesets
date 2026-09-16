rule TTP_XOR_MULT_DOSStub_ea49 {
  strings:
    $key_ea49 = { be 21 [2] ca 39 [2] 8d 3b [2] ca 2a [2] 84 26 [2] 88 2c [2] 9f 27 [2] 84 69 [2] b9 }

  condition:
    any of them
}