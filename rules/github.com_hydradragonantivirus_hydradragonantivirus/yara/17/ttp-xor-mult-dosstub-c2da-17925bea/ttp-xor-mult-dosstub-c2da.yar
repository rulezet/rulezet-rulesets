rule TTP_XOR_MULT_DOSStub_c2da {
  strings:
    $key_c2da = { 96 b2 [2] e2 aa [2] a5 a8 [2] e2 b9 [2] ac b5 [2] a0 bf [2] b7 b4 [2] ac fa [2] 91 }

  condition:
    any of them
}