rule TTP_XOR_MULT_DOSStub_ea2a {
  strings:
    $key_ea2a = { be 42 [2] ca 5a [2] 8d 58 [2] ca 49 [2] 84 45 [2] 88 4f [2] 9f 44 [2] 84 0a [2] b9 }

  condition:
    any of them
}