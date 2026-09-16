rule TTP_XOR_MULT_DOSStub_d8ed {
  strings:
    $key_d8ed = { 8c 85 [2] f8 9d [2] bf 9f [2] f8 8e [2] b6 82 [2] ba 88 [2] ad 83 [2] b6 cd [2] 8b }

  condition:
    any of them
}