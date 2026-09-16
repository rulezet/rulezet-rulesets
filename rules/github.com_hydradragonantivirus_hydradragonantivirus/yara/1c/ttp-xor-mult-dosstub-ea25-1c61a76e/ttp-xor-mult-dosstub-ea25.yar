rule TTP_XOR_MULT_DOSStub_ea25 {
  strings:
    $key_ea25 = { be 4d [2] ca 55 [2] 8d 57 [2] ca 46 [2] 84 4a [2] 88 40 [2] 9f 4b [2] 84 05 [2] b9 }

  condition:
    any of them
}