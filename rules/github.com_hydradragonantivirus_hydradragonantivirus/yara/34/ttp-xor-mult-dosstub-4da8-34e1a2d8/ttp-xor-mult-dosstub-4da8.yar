rule TTP_XOR_MULT_DOSStub_4da8 {
  strings:
    $key_4da8 = { 19 c0 [2] 6d d8 [2] 2a da [2] 6d cb [2] 23 c7 [2] 2f cd [2] 38 c6 [2] 23 88 [2] 1e }

  condition:
    any of them
}