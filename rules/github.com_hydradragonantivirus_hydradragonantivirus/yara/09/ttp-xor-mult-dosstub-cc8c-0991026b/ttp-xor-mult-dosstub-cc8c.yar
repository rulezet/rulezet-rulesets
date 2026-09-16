rule TTP_XOR_MULT_DOSStub_cc8c {
  strings:
    $key_cc8c = { 98 e4 [2] ec fc [2] ab fe [2] ec ef [2] a2 e3 [2] ae e9 [2] b9 e2 [2] a2 ac [2] 9f }

  condition:
    any of them
}