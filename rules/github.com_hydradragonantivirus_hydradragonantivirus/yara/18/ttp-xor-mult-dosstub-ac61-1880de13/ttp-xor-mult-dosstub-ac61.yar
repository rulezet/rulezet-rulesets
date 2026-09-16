rule TTP_XOR_MULT_DOSStub_ac61 {
  strings:
    $key_ac61 = { f8 09 [2] 8c 11 [2] cb 13 [2] 8c 02 [2] c2 0e [2] ce 04 [2] d9 0f [2] c2 41 [2] ff }

  condition:
    any of them
}