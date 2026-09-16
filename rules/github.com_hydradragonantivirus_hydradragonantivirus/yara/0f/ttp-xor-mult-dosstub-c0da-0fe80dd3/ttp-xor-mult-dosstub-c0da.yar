rule TTP_XOR_MULT_DOSStub_c0da {
  strings:
    $key_c0da = { 94 b2 [2] e0 aa [2] a7 a8 [2] e0 b9 [2] ae b5 [2] a2 bf [2] b5 b4 [2] ae fa [2] 93 }

  condition:
    any of them
}