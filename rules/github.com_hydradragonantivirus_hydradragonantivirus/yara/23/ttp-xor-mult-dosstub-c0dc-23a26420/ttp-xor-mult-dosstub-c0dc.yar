rule TTP_XOR_MULT_DOSStub_c0dc {
  strings:
    $key_c0dc = { 94 b4 [2] e0 ac [2] a7 ae [2] e0 bf [2] ae b3 [2] a2 b9 [2] b5 b2 [2] ae fc [2] 93 }

  condition:
    any of them
}