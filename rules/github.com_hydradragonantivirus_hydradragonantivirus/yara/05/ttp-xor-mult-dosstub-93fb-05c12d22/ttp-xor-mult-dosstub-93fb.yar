rule TTP_XOR_MULT_DOSStub_93fb {
  strings:
    $key_93fb = { c7 93 [2] b3 8b [2] f4 89 [2] b3 98 [2] fd 94 [2] f1 9e [2] e6 95 [2] fd db [2] c0 }

  condition:
    any of them
}