rule TTP_XOR_MULT_DOSStub_a8d8 {
  strings:
    $key_a8d8 = { fc b0 [2] 88 a8 [2] cf aa [2] 88 bb [2] c6 b7 [2] ca bd [2] dd b6 [2] c6 f8 [2] fb }

  condition:
    any of them
}