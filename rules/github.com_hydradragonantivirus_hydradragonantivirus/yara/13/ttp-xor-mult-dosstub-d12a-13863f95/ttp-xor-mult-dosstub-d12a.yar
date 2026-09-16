rule TTP_XOR_MULT_DOSStub_d12a {
  strings:
    $key_d12a = { 85 42 [2] f1 5a [2] b6 58 [2] f1 49 [2] bf 45 [2] b3 4f [2] a4 44 [2] bf 0a [2] 82 }

  condition:
    any of them
}