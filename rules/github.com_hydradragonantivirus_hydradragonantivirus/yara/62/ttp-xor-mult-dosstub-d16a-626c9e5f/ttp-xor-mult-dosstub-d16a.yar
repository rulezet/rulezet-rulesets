rule TTP_XOR_MULT_DOSStub_d16a {
  strings:
    $key_d16a = { 85 02 [2] f1 1a [2] b6 18 [2] f1 09 [2] bf 05 [2] b3 0f [2] a4 04 [2] bf 4a [2] 82 }

  condition:
    any of them
}