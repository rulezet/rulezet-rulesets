rule TTP_XOR_MULT_DOSStub_ea6b {
  strings:
    $key_ea6b = { be 03 [2] ca 1b [2] 8d 19 [2] ca 08 [2] 84 04 [2] 88 0e [2] 9f 05 [2] 84 4b [2] b9 }

  condition:
    any of them
}