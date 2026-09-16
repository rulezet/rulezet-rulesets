rule TTP_XOR_MULT_DOSStub_ea38 {
  strings:
    $key_ea38 = { be 50 [2] ca 48 [2] 8d 4a [2] ca 5b [2] 84 57 [2] 88 5d [2] 9f 56 [2] 84 18 [2] b9 }

  condition:
    any of them
}