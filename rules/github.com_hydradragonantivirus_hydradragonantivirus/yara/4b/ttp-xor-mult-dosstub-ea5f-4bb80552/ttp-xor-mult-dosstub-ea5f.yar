rule TTP_XOR_MULT_DOSStub_ea5f {
  strings:
    $key_ea5f = { be 37 [2] ca 2f [2] 8d 2d [2] ca 3c [2] 84 30 [2] 88 3a [2] 9f 31 [2] 84 7f [2] b9 }

  condition:
    any of them
}