rule TTP_XOR_MULT_DOSStub_ea6c {
  strings:
    $key_ea6c = { be 04 [2] ca 1c [2] 8d 1e [2] ca 0f [2] 84 03 [2] 88 09 [2] 9f 02 [2] 84 4c [2] b9 }

  condition:
    any of them
}