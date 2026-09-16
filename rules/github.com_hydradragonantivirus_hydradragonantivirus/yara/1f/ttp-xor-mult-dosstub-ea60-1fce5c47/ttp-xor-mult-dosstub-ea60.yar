rule TTP_XOR_MULT_DOSStub_ea60 {
  strings:
    $key_ea60 = { be 08 [2] ca 10 [2] 8d 12 [2] ca 03 [2] 84 0f [2] 88 05 [2] 9f 0e [2] 84 40 [2] b9 }

  condition:
    any of them
}