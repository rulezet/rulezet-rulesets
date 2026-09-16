rule TTP_XOR_MULT_DOSStub_c0c4 {
  strings:
    $key_c0c4 = { 94 ac [2] e0 b4 [2] a7 b6 [2] e0 a7 [2] ae ab [2] a2 a1 [2] b5 aa [2] ae e4 [2] 93 }

  condition:
    any of them
}