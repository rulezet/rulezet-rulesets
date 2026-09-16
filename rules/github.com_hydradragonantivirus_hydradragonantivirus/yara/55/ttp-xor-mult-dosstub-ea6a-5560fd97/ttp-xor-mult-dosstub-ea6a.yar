rule TTP_XOR_MULT_DOSStub_ea6a {
  strings:
    $key_ea6a = { be 02 [2] ca 1a [2] 8d 18 [2] ca 09 [2] 84 05 [2] 88 0f [2] 9f 04 [2] 84 4a [2] b9 }

  condition:
    any of them
}