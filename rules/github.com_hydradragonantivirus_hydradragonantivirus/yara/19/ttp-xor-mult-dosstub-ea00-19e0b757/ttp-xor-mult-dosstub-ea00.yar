rule TTP_XOR_MULT_DOSStub_ea00 {
  strings:
    $key_ea00 = { be 68 [2] ca 70 [2] 8d 72 [2] ca 63 [2] 84 6f [2] 88 65 [2] 9f 6e [2] 84 20 [2] b9 }

  condition:
    any of them
}