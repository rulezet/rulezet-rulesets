rule TTP_XOR_MULT_DOSStub_d12f {
  strings:
    $key_d12f = { 85 47 [2] f1 5f [2] b6 5d [2] f1 4c [2] bf 40 [2] b3 4a [2] a4 41 [2] bf 0f [2] 82 }

  condition:
    any of them
}