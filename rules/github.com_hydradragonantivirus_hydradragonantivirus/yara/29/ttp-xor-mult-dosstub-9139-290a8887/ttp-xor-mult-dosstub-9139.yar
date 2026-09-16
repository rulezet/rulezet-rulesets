rule TTP_XOR_MULT_DOSStub_9139 {
  strings:
    $key_9139 = { c5 51 [2] b1 49 [2] f6 4b [2] b1 5a [2] ff 56 [2] f3 5c [2] e4 57 [2] ff 19 [2] c2 }

  condition:
    any of them
}