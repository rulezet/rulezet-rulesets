rule TTP_XOR_MULT_DOSStub_ea35 {
  strings:
    $key_ea35 = { be 5d [2] ca 45 [2] 8d 47 [2] ca 56 [2] 84 5a [2] 88 50 [2] 9f 5b [2] 84 15 [2] b9 }

  condition:
    any of them
}