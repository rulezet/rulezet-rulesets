rule TTP_XOR_MULT_DOSStub_f3ba {
  strings:
    $key_f3ba = { a7 d2 [2] d3 ca [2] 94 c8 [2] d3 d9 [2] 9d d5 [2] 91 df [2] 86 d4 [2] 9d 9a [2] a0 }

  condition:
    any of them
}