rule TTP_XOR_MULT_DOSStub_d42c {
  strings:
    $key_d42c = { 80 44 [2] f4 5c [2] b3 5e [2] f4 4f [2] ba 43 [2] b6 49 [2] a1 42 [2] ba 0c [2] 87 }

  condition:
    any of them
}