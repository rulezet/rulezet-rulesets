rule TTP_XOR_MULT_DOSStub_ea16 {
  strings:
    $key_ea16 = { be 7e [2] ca 66 [2] 8d 64 [2] ca 75 [2] 84 79 [2] 88 73 [2] 9f 78 [2] 84 36 [2] b9 }

  condition:
    any of them
}