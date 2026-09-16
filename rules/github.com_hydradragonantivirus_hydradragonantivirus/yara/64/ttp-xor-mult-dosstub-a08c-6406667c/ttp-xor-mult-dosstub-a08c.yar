rule TTP_XOR_MULT_DOSStub_a08c {
  strings:
    $key_a08c = { f4 e4 [2] 80 fc [2] c7 fe [2] 80 ef [2] ce e3 [2] c2 e9 [2] d5 e2 [2] ce ac [2] f3 }

  condition:
    any of them
}