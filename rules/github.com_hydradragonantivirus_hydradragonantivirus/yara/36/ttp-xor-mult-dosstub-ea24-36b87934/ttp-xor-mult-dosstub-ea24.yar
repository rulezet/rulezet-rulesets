rule TTP_XOR_MULT_DOSStub_ea24 {
  strings:
    $key_ea24 = { be 4c [2] ca 54 [2] 8d 56 [2] ca 47 [2] 84 4b [2] 88 41 [2] 9f 4a [2] 84 04 [2] b9 }

  condition:
    any of them
}