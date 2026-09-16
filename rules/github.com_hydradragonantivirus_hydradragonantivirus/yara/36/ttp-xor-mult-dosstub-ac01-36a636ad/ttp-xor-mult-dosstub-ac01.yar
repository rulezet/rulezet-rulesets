rule TTP_XOR_MULT_DOSStub_ac01 {
  strings:
    $key_ac01 = { f8 69 [2] 8c 71 [2] cb 73 [2] 8c 62 [2] c2 6e [2] ce 64 [2] d9 6f [2] c2 21 [2] ff }

  condition:
    any of them
}