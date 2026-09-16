rule TTP_XOR_MULT_DOSStub_913c {
  strings:
    $key_913c = { c5 54 [2] b1 4c [2] f6 4e [2] b1 5f [2] ff 53 [2] f3 59 [2] e4 52 [2] ff 1c [2] c2 }

  condition:
    any of them
}