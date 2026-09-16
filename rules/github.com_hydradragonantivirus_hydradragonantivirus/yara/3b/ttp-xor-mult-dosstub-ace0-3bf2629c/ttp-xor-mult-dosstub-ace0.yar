rule TTP_XOR_MULT_DOSStub_ace0 {
  strings:
    $key_ace0 = { f8 88 [2] 8c 90 [2] cb 92 [2] 8c 83 [2] c2 8f [2] ce 85 [2] d9 8e [2] c2 c0 [2] ff }

  condition:
    any of them
}