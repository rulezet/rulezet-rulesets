rule TTP_XOR_MULT_DOSStub_ed8c {
  strings:
    $key_ed8c = { b9 e4 [2] cd fc [2] 8a fe [2] cd ef [2] 83 e3 [2] 8f e9 [2] 98 e2 [2] 83 ac [2] be }

  condition:
    any of them
}