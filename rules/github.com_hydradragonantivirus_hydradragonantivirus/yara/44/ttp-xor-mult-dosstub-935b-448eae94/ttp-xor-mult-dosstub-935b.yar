rule TTP_XOR_MULT_DOSStub_935b {
  strings:
    $key_935b = { c7 33 [2] b3 2b [2] f4 29 [2] b3 38 [2] fd 34 [2] f1 3e [2] e6 35 [2] fd 7b [2] c0 }

  condition:
    any of them
}