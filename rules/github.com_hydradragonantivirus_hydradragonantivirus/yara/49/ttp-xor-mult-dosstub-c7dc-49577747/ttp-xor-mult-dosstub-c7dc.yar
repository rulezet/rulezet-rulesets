rule TTP_XOR_MULT_DOSStub_c7dc {
  strings:
    $key_c7dc = { 93 b4 [2] e7 ac [2] a0 ae [2] e7 bf [2] a9 b3 [2] a5 b9 [2] b2 b2 [2] a9 fc [2] 94 }

  condition:
    any of them
}