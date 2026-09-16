rule TTP_XOR_MULT_DOSStub_e6dc {
  strings:
    $key_e6dc = { b2 b4 [2] c6 ac [2] 81 ae [2] c6 bf [2] 88 b3 [2] 84 b9 [2] 93 b2 [2] 88 fc [2] b5 }

  condition:
    any of them
}