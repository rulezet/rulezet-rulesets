rule TTP_XOR_MULT_DOSStub_b2dc {
  strings:
    $key_b2dc = { e6 b4 [2] 92 ac [2] d5 ae [2] 92 bf [2] dc b3 [2] d0 b9 [2] c7 b2 [2] dc fc [2] e1 }

  condition:
    any of them
}