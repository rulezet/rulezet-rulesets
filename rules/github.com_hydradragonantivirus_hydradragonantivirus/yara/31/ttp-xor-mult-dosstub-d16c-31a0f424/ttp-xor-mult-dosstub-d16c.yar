rule TTP_XOR_MULT_DOSStub_d16c {
  strings:
    $key_d16c = { 85 04 [2] f1 1c [2] b6 1e [2] f1 0f [2] bf 03 [2] b3 09 [2] a4 02 [2] bf 4c [2] 82 }

  condition:
    any of them
}