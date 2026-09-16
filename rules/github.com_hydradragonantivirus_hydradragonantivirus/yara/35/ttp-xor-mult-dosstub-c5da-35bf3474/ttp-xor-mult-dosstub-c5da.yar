rule TTP_XOR_MULT_DOSStub_c5da {
  strings:
    $key_c5da = { 91 b2 [2] e5 aa [2] a2 a8 [2] e5 b9 [2] ab b5 [2] a7 bf [2] b0 b4 [2] ab fa [2] 96 }

  condition:
    any of them
}