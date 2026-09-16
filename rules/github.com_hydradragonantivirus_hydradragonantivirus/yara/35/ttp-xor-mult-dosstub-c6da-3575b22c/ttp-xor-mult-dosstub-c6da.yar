rule TTP_XOR_MULT_DOSStub_c6da {
  strings:
    $key_c6da = { 92 b2 [2] e6 aa [2] a1 a8 [2] e6 b9 [2] a8 b5 [2] a4 bf [2] b3 b4 [2] a8 fa [2] 95 }

  condition:
    any of them
}