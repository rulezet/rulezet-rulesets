rule TTP_XOR_MULT_DOSStub_ea1e {
  strings:
    $key_ea1e = { be 76 [2] ca 6e [2] 8d 6c [2] ca 7d [2] 84 71 [2] 88 7b [2] 9f 70 [2] 84 3e [2] b9 }

  condition:
    any of them
}