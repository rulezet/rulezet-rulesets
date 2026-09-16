rule TTP_XOR_MULT_DOSStub_ea1f {
  strings:
    $key_ea1f = { be 77 [2] ca 6f [2] 8d 6d [2] ca 7c [2] 84 70 [2] 88 7a [2] 9f 71 [2] 84 3f [2] b9 }

  condition:
    any of them
}