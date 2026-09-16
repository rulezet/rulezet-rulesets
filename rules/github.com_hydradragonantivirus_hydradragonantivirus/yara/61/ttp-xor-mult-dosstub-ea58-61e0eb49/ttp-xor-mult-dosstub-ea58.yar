rule TTP_XOR_MULT_DOSStub_ea58 {
  strings:
    $key_ea58 = { be 30 [2] ca 28 [2] 8d 2a [2] ca 3b [2] 84 37 [2] 88 3d [2] 9f 36 [2] 84 78 [2] b9 }

  condition:
    any of them
}