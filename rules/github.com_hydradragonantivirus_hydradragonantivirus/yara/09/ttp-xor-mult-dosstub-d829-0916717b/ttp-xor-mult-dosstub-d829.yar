rule TTP_XOR_MULT_DOSStub_d829 {
  strings:
    $key_d829 = { 8c 41 [2] f8 59 [2] bf 5b [2] f8 4a [2] b6 46 [2] ba 4c [2] ad 47 [2] b6 09 [2] 8b }

  condition:
    any of them
}