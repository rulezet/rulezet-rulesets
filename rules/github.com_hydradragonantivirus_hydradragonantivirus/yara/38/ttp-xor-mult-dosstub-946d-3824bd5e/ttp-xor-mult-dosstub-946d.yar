rule TTP_XOR_MULT_DOSStub_946d {
  strings:
    $key_946d = { c0 05 [2] b4 1d [2] f3 1f [2] b4 0e [2] fa 02 [2] f6 08 [2] e1 03 [2] fa 4d [2] c7 }

  condition:
    any of them
}