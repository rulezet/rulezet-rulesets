rule TTP_XOR_MULT_DOSStub_0da8 {
  strings:
    $key_0da8 = { 59 c0 [2] 2d d8 [2] 6a da [2] 2d cb [2] 63 c7 [2] 6f cd [2] 78 c6 [2] 63 88 [2] 5e }

  condition:
    any of them
}