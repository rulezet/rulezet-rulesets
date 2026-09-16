rule TTP_XOR_MULT_DOSStub_ea4b {
  strings:
    $key_ea4b = { be 23 [2] ca 3b [2] 8d 39 [2] ca 28 [2] 84 24 [2] 88 2e [2] 9f 25 [2] 84 6b [2] b9 }

  condition:
    any of them
}