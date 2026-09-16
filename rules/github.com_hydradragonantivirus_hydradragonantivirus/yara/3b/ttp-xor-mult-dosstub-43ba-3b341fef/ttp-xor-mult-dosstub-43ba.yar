rule TTP_XOR_MULT_DOSStub_43ba {
  strings:
    $key_43ba = { 17 d2 [2] 63 ca [2] 24 c8 [2] 63 d9 [2] 2d d5 [2] 21 df [2] 36 d4 [2] 2d 9a [2] 10 }

  condition:
    any of them
}