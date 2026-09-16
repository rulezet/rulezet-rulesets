rule TTP_XOR_MULT_DOSStub_ea8c {
  strings:
    $key_ea8c = { be e4 [2] ca fc [2] 8d fe [2] ca ef [2] 84 e3 [2] 88 e9 [2] 9f e2 [2] 84 ac [2] b9 }

  condition:
    any of them
}