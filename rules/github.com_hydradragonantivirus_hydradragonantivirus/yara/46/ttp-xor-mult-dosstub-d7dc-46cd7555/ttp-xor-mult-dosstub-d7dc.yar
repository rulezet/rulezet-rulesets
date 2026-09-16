rule TTP_XOR_MULT_DOSStub_d7dc {
  strings:
    $key_d7dc = { 83 b4 [2] f7 ac [2] b0 ae [2] f7 bf [2] b9 b3 [2] b5 b9 [2] a2 b2 [2] b9 fc [2] 84 }

  condition:
    any of them
}