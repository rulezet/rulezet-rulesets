rule TTP_XOR_MULT_DOSStub_acff {
  strings:
    $key_acff = { f8 97 [2] 8c 8f [2] cb 8d [2] 8c 9c [2] c2 90 [2] ce 9a [2] d9 91 [2] c2 df [2] ff }

  condition:
    any of them
}