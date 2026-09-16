rule TTP_XOR_MULT_DOSStub_ea01 {
  strings:
    $key_ea01 = { be 69 [2] ca 71 [2] 8d 73 [2] ca 62 [2] 84 6e [2] 88 64 [2] 9f 6f [2] 84 21 [2] b9 }

  condition:
    any of them
}