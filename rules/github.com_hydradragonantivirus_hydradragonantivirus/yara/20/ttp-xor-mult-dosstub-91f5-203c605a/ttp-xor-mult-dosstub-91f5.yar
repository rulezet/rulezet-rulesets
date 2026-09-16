rule TTP_XOR_MULT_DOSStub_91f5 {
  strings:
    $key_91f5 = { c5 9d [2] b1 85 [2] f6 87 [2] b1 96 [2] ff 9a [2] f3 90 [2] e4 9b [2] ff d5 [2] c2 }

  condition:
    any of them
}