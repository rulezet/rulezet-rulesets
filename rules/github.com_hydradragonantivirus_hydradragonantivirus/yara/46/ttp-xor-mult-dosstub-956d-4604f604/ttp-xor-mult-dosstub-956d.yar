rule TTP_XOR_MULT_DOSStub_956d {
  strings:
    $key_956d = { c1 05 [2] b5 1d [2] f2 1f [2] b5 0e [2] fb 02 [2] f7 08 [2] e0 03 [2] fb 4d [2] c6 }

  condition:
    any of them
}