rule TTP_XOR_MULT_DOSStub_ac67 {
  strings:
    $key_ac67 = { f8 0f [2] 8c 17 [2] cb 15 [2] 8c 04 [2] c2 08 [2] ce 02 [2] d9 09 [2] c2 47 [2] ff }

  condition:
    any of them
}