rule TTP_XOR_MULT_DOSStub_facb {
  strings:
    $key_facb = { ae a3 [2] da bb [2] 9d b9 [2] da a8 [2] 94 a4 [2] 98 ae [2] 8f a5 [2] 94 eb [2] a9 }

  condition:
    any of them
}