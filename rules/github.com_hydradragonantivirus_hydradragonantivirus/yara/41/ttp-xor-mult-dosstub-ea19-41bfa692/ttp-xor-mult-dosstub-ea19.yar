rule TTP_XOR_MULT_DOSStub_ea19 {
  strings:
    $key_ea19 = { be 71 [2] ca 69 [2] 8d 6b [2] ca 7a [2] 84 76 [2] 88 7c [2] 9f 77 [2] 84 39 [2] b9 }

  condition:
    any of them
}