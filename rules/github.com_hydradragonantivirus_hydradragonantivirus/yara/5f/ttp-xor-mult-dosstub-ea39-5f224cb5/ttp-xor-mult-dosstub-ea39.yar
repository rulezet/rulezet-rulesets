rule TTP_XOR_MULT_DOSStub_ea39 {
  strings:
    $key_ea39 = { be 51 [2] ca 49 [2] 8d 4b [2] ca 5a [2] 84 56 [2] 88 5c [2] 9f 57 [2] 84 19 [2] b9 }

  condition:
    any of them
}