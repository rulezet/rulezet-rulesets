rule TTP_XOR_MULT_DOSStub_ea68 {
  strings:
    $key_ea68 = { be 00 [2] ca 18 [2] 8d 1a [2] ca 0b [2] 84 07 [2] 88 0d [2] 9f 06 [2] 84 48 [2] b9 }

  condition:
    any of them
}