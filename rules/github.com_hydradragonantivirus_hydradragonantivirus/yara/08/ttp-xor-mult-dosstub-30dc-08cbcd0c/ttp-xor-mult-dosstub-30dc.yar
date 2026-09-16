rule TTP_XOR_MULT_DOSStub_30dc {
  strings:
    $key_30dc = { 64 b4 [2] 10 ac [2] 57 ae [2] 10 bf [2] 5e b3 [2] 52 b9 [2] 45 b2 [2] 5e fc [2] 63 }

  condition:
    any of them
}