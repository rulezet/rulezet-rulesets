rule TTP_XOR_MULT_DOSStub_ea7b {
  strings:
    $key_ea7b = { be 13 [2] ca 0b [2] 8d 09 [2] ca 18 [2] 84 14 [2] 88 1e [2] 9f 15 [2] 84 5b [2] b9 }

  condition:
    any of them
}