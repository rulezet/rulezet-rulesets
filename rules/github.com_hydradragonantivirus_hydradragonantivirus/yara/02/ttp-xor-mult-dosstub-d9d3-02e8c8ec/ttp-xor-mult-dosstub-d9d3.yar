rule TTP_XOR_MULT_DOSStub_d9d3 {
  strings:
    $key_d9d3 = { 8d bb [2] f9 a3 [2] be a1 [2] f9 b0 [2] b7 bc [2] bb b6 [2] ac bd [2] b7 f3 [2] 8a }

  condition:
    any of them
}