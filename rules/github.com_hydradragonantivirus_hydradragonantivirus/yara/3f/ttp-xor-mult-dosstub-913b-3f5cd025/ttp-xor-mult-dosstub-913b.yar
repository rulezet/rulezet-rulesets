rule TTP_XOR_MULT_DOSStub_913b {
  strings:
    $key_913b = { c5 53 [2] b1 4b [2] f6 49 [2] b1 58 [2] ff 54 [2] f3 5e [2] e4 55 [2] ff 1b [2] c2 }

  condition:
    any of them
}