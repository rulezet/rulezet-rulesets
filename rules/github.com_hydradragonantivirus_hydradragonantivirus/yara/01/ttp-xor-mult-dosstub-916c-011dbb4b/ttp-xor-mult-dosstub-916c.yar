rule TTP_XOR_MULT_DOSStub_916c {
  strings:
    $key_916c = { c5 04 [2] b1 1c [2] f6 1e [2] b1 0f [2] ff 03 [2] f3 09 [2] e4 02 [2] ff 4c [2] c2 }

  condition:
    any of them
}