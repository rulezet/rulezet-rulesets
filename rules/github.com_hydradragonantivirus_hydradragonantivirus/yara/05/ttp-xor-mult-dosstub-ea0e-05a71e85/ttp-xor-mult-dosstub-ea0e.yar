rule TTP_XOR_MULT_DOSStub_ea0e {
  strings:
    $key_ea0e = { be 66 [2] ca 7e [2] 8d 7c [2] ca 6d [2] 84 61 [2] 88 6b [2] 9f 60 [2] 84 2e [2] b9 }

  condition:
    any of them
}