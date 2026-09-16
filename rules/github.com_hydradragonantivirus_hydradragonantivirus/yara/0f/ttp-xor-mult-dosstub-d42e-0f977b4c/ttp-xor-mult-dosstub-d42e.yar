rule TTP_XOR_MULT_DOSStub_d42e {
  strings:
    $key_d42e = { 80 46 [2] f4 5e [2] b3 5c [2] f4 4d [2] ba 41 [2] b6 4b [2] a1 40 [2] ba 0e [2] 87 }

  condition:
    any of them
}