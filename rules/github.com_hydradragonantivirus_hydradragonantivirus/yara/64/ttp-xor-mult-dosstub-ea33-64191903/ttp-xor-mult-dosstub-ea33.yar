rule TTP_XOR_MULT_DOSStub_ea33 {
  strings:
    $key_ea33 = { be 5b [2] ca 43 [2] 8d 41 [2] ca 50 [2] 84 5c [2] 88 56 [2] 9f 5d [2] 84 13 [2] b9 }

  condition:
    any of them
}