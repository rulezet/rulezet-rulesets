rule TTP_XOR_MULT_DOSStub_468c {
  strings:
    $key_468c = { 12 e4 [2] 66 fc [2] 21 fe [2] 66 ef [2] 28 e3 [2] 24 e9 [2] 33 e2 [2] 28 ac [2] 15 }

  condition:
    any of them
}