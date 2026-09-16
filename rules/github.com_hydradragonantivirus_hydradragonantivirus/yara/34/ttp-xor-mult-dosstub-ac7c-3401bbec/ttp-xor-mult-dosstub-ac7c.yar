rule TTP_XOR_MULT_DOSStub_ac7c {
  strings:
    $key_ac7c = { f8 14 [2] 8c 0c [2] cb 0e [2] 8c 1f [2] c2 13 [2] ce 19 [2] d9 12 [2] c2 5c [2] ff }

  condition:
    any of them
}