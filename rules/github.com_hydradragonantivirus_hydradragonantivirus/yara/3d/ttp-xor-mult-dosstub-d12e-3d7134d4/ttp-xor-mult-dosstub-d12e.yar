rule TTP_XOR_MULT_DOSStub_d12e {
  strings:
    $key_d12e = { 85 46 [2] f1 5e [2] b6 5c [2] f1 4d [2] bf 41 [2] b3 4b [2] a4 40 [2] bf 0e [2] 82 }

  condition:
    any of them
}