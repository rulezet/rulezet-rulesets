rule TTP_XOR_MULT_DOSStub_27dc {
  strings:
    $key_27dc = { 73 b4 [2] 07 ac [2] 40 ae [2] 07 bf [2] 49 b3 [2] 45 b9 [2] 52 b2 [2] 49 fc [2] 74 }

  condition:
    any of them
}