rule TTP_XOR_MULT_DOSStub_d6dc {
  strings:
    $key_d6dc = { 82 b4 [2] f6 ac [2] b1 ae [2] f6 bf [2] b8 b3 [2] b4 b9 [2] a3 b2 [2] b8 fc [2] 85 }

  condition:
    any of them
}