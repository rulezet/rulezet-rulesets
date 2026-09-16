rule TTP_XOR_MULT_DOSStub_ea4c {
  strings:
    $key_ea4c = { be 24 [2] ca 3c [2] 8d 3e [2] ca 2f [2] 84 23 [2] 88 29 [2] 9f 22 [2] 84 6c [2] b9 }

  condition:
    any of them
}