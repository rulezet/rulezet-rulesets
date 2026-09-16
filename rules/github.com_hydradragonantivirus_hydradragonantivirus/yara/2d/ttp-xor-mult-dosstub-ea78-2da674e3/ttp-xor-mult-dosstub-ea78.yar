rule TTP_XOR_MULT_DOSStub_ea78 {
  strings:
    $key_ea78 = { be 10 [2] ca 08 [2] 8d 0a [2] ca 1b [2] 84 17 [2] 88 1d [2] 9f 16 [2] 84 58 [2] b9 }

  condition:
    any of them
}