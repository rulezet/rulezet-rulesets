rule TTP_XOR_MULT_DOSStub_f0dc {
  strings:
    $key_f0dc = { a4 b4 [2] d0 ac [2] 97 ae [2] d0 bf [2] 9e b3 [2] 92 b9 [2] 85 b2 [2] 9e fc [2] a3 }

  condition:
    any of them
}