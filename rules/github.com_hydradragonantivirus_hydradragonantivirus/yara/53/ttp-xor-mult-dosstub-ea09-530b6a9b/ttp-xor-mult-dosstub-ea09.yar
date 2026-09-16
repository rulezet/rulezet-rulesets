rule TTP_XOR_MULT_DOSStub_ea09 {
  strings:
    $key_ea09 = { be 61 [2] ca 79 [2] 8d 7b [2] ca 6a [2] 84 66 [2] 88 6c [2] 9f 67 [2] 84 29 [2] b9 }

  condition:
    any of them
}