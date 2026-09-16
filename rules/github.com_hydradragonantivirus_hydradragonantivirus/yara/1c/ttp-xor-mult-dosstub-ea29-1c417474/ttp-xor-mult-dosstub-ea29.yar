rule TTP_XOR_MULT_DOSStub_ea29 {
  strings:
    $key_ea29 = { be 41 [2] ca 59 [2] 8d 5b [2] ca 4a [2] 84 46 [2] 88 4c [2] 9f 47 [2] 84 09 [2] b9 }

  condition:
    any of them
}