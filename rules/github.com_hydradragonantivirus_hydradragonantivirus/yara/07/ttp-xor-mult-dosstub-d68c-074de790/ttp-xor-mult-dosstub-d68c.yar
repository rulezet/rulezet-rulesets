rule TTP_XOR_MULT_DOSStub_d68c {
  strings:
    $key_d68c = { 82 e4 [2] f6 fc [2] b1 fe [2] f6 ef [2] b8 e3 [2] b4 e9 [2] a3 e2 [2] b8 ac [2] 85 }

  condition:
    any of them
}