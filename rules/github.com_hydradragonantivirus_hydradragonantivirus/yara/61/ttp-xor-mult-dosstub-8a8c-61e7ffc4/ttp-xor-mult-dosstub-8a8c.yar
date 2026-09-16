rule TTP_XOR_MULT_DOSStub_8a8c {
  strings:
    $key_8a8c = { de e4 [2] aa fc [2] ed fe [2] aa ef [2] e4 e3 [2] e8 e9 [2] ff e2 [2] e4 ac [2] d9 }

  condition:
    any of them
}