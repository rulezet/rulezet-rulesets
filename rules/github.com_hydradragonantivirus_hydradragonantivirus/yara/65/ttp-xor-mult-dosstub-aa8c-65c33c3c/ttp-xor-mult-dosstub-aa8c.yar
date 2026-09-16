rule TTP_XOR_MULT_DOSStub_aa8c {
  strings:
    $key_aa8c = { fe e4 [2] 8a fc [2] cd fe [2] 8a ef [2] c4 e3 [2] c8 e9 [2] df e2 [2] c4 ac [2] f9 }

  condition:
    any of them
}