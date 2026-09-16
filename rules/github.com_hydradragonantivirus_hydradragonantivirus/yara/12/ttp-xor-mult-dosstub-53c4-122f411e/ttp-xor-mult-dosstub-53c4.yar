rule TTP_XOR_MULT_DOSStub_53c4 {
  strings:
    $key_53c4 = { 07 ac [2] 73 b4 [2] 34 b6 [2] 73 a7 [2] 3d ab [2] 31 a1 [2] 26 aa [2] 3d e4 [2] 00 }

  condition:
    any of them
}