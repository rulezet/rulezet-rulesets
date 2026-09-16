rule TTP_XOR_MULT_DOSStub_ea62 {
  strings:
    $key_ea62 = { be 0a [2] ca 12 [2] 8d 10 [2] ca 01 [2] 84 0d [2] 88 07 [2] 9f 0c [2] 84 42 [2] b9 }

  condition:
    any of them
}