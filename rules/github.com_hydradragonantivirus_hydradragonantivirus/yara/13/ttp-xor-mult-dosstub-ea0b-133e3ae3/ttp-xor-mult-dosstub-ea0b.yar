rule TTP_XOR_MULT_DOSStub_ea0b {
  strings:
    $key_ea0b = { be 63 [2] ca 7b [2] 8d 79 [2] ca 68 [2] 84 64 [2] 88 6e [2] 9f 65 [2] 84 2b [2] b9 }

  condition:
    any of them
}