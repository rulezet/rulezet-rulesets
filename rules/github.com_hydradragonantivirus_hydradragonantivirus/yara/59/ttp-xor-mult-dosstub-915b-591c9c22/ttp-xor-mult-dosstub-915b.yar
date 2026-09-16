rule TTP_XOR_MULT_DOSStub_915b {
  strings:
    $key_915b = { c5 33 [2] b1 2b [2] f6 29 [2] b1 38 [2] ff 34 [2] f3 3e [2] e4 35 [2] ff 7b [2] c2 }

  condition:
    any of them
}