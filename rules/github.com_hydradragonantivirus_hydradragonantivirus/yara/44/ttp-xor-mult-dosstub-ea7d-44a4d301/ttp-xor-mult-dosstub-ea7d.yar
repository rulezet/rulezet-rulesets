rule TTP_XOR_MULT_DOSStub_ea7d {
  strings:
    $key_ea7d = { be 15 [2] ca 0d [2] 8d 0f [2] ca 1e [2] 84 12 [2] 88 18 [2] 9f 13 [2] 84 5d [2] b9 }

  condition:
    any of them
}