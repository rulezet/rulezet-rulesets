rule TTP_XOR_MULT_DOSStub_d823 {
  strings:
    $key_d823 = { 8c 4b [2] f8 53 [2] bf 51 [2] f8 40 [2] b6 4c [2] ba 46 [2] ad 4d [2] b6 03 [2] 8b }

  condition:
    any of them
}