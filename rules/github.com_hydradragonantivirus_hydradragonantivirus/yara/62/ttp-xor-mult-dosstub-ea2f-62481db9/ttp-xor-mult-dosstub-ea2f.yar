rule TTP_XOR_MULT_DOSStub_ea2f {
  strings:
    $key_ea2f = { be 47 [2] ca 5f [2] 8d 5d [2] ca 4c [2] 84 40 [2] 88 4a [2] 9f 41 [2] 84 0f [2] b9 }

  condition:
    any of them
}