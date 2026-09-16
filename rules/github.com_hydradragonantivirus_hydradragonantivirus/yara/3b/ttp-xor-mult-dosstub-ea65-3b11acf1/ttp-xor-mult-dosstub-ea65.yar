rule TTP_XOR_MULT_DOSStub_ea65 {
  strings:
    $key_ea65 = { be 0d [2] ca 15 [2] 8d 17 [2] ca 06 [2] 84 0a [2] 88 00 [2] 9f 0b [2] 84 45 [2] b9 }

  condition:
    any of them
}