rule TTP_XOR_MULT_DOSStub_7da8 {
  strings:
    $key_7da8 = { 29 c0 [2] 5d d8 [2] 1a da [2] 5d cb [2] 13 c7 [2] 1f cd [2] 08 c6 [2] 13 88 [2] 2e }

  condition:
    any of them
}