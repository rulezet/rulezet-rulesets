rule TTP_XOR_MULT_DOSStub_d49c {
  strings:
    $key_d49c = { 80 f4 [2] f4 ec [2] b3 ee [2] f4 ff [2] ba f3 [2] b6 f9 [2] a1 f2 [2] ba bc [2] 87 }

  condition:
    any of them
}