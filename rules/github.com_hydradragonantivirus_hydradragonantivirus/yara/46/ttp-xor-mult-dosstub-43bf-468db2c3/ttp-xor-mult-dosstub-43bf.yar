rule TTP_XOR_MULT_DOSStub_43bf {
  strings:
    $key_43bf = { 17 d7 [2] 63 cf [2] 24 cd [2] 63 dc [2] 2d d0 [2] 21 da [2] 36 d1 [2] 2d 9f [2] 10 }

  condition:
    any of them
}