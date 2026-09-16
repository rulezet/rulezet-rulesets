rule TTP_XOR_MULT_DOSStub_f8d3 {
  strings:
    $key_f8d3 = { ac bb [2] d8 a3 [2] 9f a1 [2] d8 b0 [2] 96 bc [2] 9a b6 [2] 8d bd [2] 96 f3 [2] ab }

  condition:
    any of them
}