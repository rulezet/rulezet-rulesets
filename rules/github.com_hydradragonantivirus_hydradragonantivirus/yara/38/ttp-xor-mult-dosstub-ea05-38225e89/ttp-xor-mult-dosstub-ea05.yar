rule TTP_XOR_MULT_DOSStub_ea05 {
  strings:
    $key_ea05 = { be 6d [2] ca 75 [2] 8d 77 [2] ca 66 [2] 84 6a [2] 88 60 [2] 9f 6b [2] 84 25 [2] b9 }

  condition:
    any of them
}