rule TTP_XOR_MULT_DOSStub_fa8c {
  strings:
    $key_fa8c = { ae e4 [2] da fc [2] 9d fe [2] da ef [2] 94 e3 [2] 98 e9 [2] 8f e2 [2] 94 ac [2] a9 }

  condition:
    any of them
}