rule TTP_XOR_MULT_DOSStub_a957 {
  strings:
    $key_a957 = { fd 3f [2] 89 27 [2] ce 25 [2] 89 34 [2] c7 38 [2] cb 32 [2] dc 39 [2] c7 77 [2] fa }

  condition:
    any of them
}