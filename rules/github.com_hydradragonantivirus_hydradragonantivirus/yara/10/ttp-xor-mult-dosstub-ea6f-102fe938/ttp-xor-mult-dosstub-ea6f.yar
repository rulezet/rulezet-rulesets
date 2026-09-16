rule TTP_XOR_MULT_DOSStub_ea6f {
  strings:
    $key_ea6f = { be 07 [2] ca 1f [2] 8d 1d [2] ca 0c [2] 84 00 [2] 88 0a [2] 9f 01 [2] 84 4f [2] b9 }

  condition:
    any of them
}