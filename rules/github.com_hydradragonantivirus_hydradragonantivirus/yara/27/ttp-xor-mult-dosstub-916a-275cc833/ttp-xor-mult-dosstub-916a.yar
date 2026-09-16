rule TTP_XOR_MULT_DOSStub_916a {
  strings:
    $key_916a = { c5 02 [2] b1 1a [2] f6 18 [2] b1 09 [2] ff 05 [2] f3 0f [2] e4 04 [2] ff 4a [2] c2 }

  condition:
    any of them
}