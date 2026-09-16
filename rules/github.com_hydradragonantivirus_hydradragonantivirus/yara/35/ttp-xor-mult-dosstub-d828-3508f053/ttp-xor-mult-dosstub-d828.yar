rule TTP_XOR_MULT_DOSStub_d828 {
  strings:
    $key_d828 = { 8c 40 [2] f8 58 [2] bf 5a [2] f8 4b [2] b6 47 [2] ba 4d [2] ad 46 [2] b6 08 [2] 8b }

  condition:
    any of them
}