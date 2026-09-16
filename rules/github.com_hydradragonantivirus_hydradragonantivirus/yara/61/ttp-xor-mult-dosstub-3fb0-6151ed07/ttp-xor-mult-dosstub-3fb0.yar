rule TTP_XOR_MULT_DOSStub_3fb0 {
  strings:
    $key_3fb0 = { 6b d8 [2] 1f c0 [2] 58 c2 [2] 1f d3 [2] 51 df [2] 5d d5 [2] 4a de [2] 51 90 [2] 6c }

  condition:
    any of them
}