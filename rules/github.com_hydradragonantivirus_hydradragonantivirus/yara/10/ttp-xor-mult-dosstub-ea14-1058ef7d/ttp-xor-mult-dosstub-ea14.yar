rule TTP_XOR_MULT_DOSStub_ea14 {
  strings:
    $key_ea14 = { be 7c [2] ca 64 [2] 8d 66 [2] ca 77 [2] 84 7b [2] 88 71 [2] 9f 7a [2] 84 34 [2] b9 }

  condition:
    any of them
}