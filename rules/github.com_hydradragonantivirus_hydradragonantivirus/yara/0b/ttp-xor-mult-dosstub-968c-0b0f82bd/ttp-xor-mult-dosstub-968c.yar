rule TTP_XOR_MULT_DOSStub_968c {
  strings:
    $key_968c = { c2 e4 [2] b6 fc [2] f1 fe [2] b6 ef [2] f8 e3 [2] f4 e9 [2] e3 e2 [2] f8 ac [2] c5 }

  condition:
    any of them
}