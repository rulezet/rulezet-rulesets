rule TTP_XOR_MULT_DOSStub_b2d8 {
  strings:
    $key_b2d8 = { e6 b0 [2] 92 a8 [2] d5 aa [2] 92 bb [2] dc b7 [2] d0 bd [2] c7 b6 [2] dc f8 [2] e1 }

  condition:
    any of them
}