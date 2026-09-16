rule TTP_XOR_MULT_DOSStub_c7da {
  strings:
    $key_c7da = { 93 b2 [2] e7 aa [2] a0 a8 [2] e7 b9 [2] a9 b5 [2] a5 bf [2] b2 b4 [2] a9 fa [2] 94 }

  condition:
    any of them
}