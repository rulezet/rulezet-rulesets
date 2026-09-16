rule TTP_XOR_MULT_DOSStub_978c {
  strings:
    $key_978c = { c3 e4 [2] b7 fc [2] f0 fe [2] b7 ef [2] f9 e3 [2] f5 e9 [2] e2 e2 [2] f9 ac [2] c4 }

  condition:
    any of them
}