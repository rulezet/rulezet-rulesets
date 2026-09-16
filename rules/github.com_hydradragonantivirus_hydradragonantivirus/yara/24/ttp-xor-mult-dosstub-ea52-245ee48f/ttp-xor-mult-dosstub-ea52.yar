rule TTP_XOR_MULT_DOSStub_ea52 {
  strings:
    $key_ea52 = { be 3a [2] ca 22 [2] 8d 20 [2] ca 31 [2] 84 3d [2] 88 37 [2] 9f 3c [2] 84 72 [2] b9 }

  condition:
    any of them
}