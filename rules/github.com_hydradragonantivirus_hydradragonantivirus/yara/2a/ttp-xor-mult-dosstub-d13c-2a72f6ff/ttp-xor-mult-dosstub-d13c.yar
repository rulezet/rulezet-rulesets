rule TTP_XOR_MULT_DOSStub_d13c {
  strings:
    $key_d13c = { 85 54 [2] f1 4c [2] b6 4e [2] f1 5f [2] bf 53 [2] b3 59 [2] a4 52 [2] bf 1c [2] 82 }

  condition:
    any of them
}