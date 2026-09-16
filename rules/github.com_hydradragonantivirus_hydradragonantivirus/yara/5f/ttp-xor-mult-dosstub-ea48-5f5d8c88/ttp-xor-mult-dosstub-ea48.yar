rule TTP_XOR_MULT_DOSStub_ea48 {
  strings:
    $key_ea48 = { be 20 [2] ca 38 [2] 8d 3a [2] ca 2b [2] 84 27 [2] 88 2d [2] 9f 26 [2] 84 68 [2] b9 }

  condition:
    any of them
}