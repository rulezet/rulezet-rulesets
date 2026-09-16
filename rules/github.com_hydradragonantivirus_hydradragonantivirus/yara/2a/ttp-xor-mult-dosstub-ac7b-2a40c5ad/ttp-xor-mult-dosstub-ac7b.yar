rule TTP_XOR_MULT_DOSStub_ac7b {
  strings:
    $key_ac7b = { f8 13 [2] 8c 0b [2] cb 09 [2] 8c 18 [2] c2 14 [2] ce 1e [2] d9 15 [2] c2 5b [2] ff }

  condition:
    any of them
}