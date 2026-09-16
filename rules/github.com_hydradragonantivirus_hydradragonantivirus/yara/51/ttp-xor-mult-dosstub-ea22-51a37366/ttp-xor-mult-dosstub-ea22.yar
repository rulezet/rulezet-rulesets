rule TTP_XOR_MULT_DOSStub_ea22 {
  strings:
    $key_ea22 = { be 4a [2] ca 52 [2] 8d 50 [2] ca 41 [2] 84 4d [2] 88 47 [2] 9f 4c [2] 84 02 [2] b9 }

  condition:
    any of them
}