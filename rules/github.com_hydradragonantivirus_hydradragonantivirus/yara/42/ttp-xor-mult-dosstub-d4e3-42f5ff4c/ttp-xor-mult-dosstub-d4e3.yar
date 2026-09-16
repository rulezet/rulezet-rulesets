rule TTP_XOR_MULT_DOSStub_d4e3 {
  strings:
    $key_d4e3 = { 80 8b [2] f4 93 [2] b3 91 [2] f4 80 [2] ba 8c [2] b6 86 [2] a1 8d [2] ba c3 [2] 87 }

  condition:
    any of them
}