rule TTP_XOR_MULT_DOSStub_ea5b {
  strings:
    $key_ea5b = { be 33 [2] ca 2b [2] 8d 29 [2] ca 38 [2] 84 34 [2] 88 3e [2] 9f 35 [2] 84 7b [2] b9 }

  condition:
    any of them
}