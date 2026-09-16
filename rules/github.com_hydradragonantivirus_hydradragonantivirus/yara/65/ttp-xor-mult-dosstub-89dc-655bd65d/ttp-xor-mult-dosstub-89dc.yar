rule TTP_XOR_MULT_DOSStub_89dc {
  strings:
    $key_89dc = { dd b4 [2] a9 ac [2] ee ae [2] a9 bf [2] e7 b3 [2] eb b9 [2] fc b2 [2] e7 fc [2] da }

  condition:
    any of them
}