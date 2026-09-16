rule TTP_XOR_MULT_DOSStub_916b {
  strings:
    $key_916b = { c5 03 [2] b1 1b [2] f6 19 [2] b1 08 [2] ff 04 [2] f3 0e [2] e4 05 [2] ff 4b [2] c2 }

  condition:
    any of them
}