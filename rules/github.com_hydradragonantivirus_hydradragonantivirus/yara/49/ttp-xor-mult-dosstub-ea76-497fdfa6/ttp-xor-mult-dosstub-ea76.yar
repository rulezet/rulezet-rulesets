rule TTP_XOR_MULT_DOSStub_ea76 {
  strings:
    $key_ea76 = { be 1e [2] ca 06 [2] 8d 04 [2] ca 15 [2] 84 19 [2] 88 13 [2] 9f 18 [2] 84 56 [2] b9 }

  condition:
    any of them
}