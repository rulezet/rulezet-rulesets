rule TTP_XOR_MULT_DOSStub_cfcb {
  strings:
    $key_cfcb = { 9b a3 [2] ef bb [2] a8 b9 [2] ef a8 [2] a1 a4 [2] ad ae [2] ba a5 [2] a1 eb [2] 9c }

  condition:
    any of them
}