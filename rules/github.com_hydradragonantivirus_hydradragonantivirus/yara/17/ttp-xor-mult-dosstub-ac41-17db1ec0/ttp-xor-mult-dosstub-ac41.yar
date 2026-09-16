rule TTP_XOR_MULT_DOSStub_ac41 {
  strings:
    $key_ac41 = { f8 29 [2] 8c 31 [2] cb 33 [2] 8c 22 [2] c2 2e [2] ce 24 [2] d9 2f [2] c2 61 [2] ff }

  condition:
    any of them
}