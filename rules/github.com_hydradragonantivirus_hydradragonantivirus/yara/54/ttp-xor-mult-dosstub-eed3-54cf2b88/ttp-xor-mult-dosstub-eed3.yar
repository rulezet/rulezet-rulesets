rule TTP_XOR_MULT_DOSStub_eed3 {
  strings:
    $key_eed3 = { ba bb [2] ce a3 [2] 89 a1 [2] ce b0 [2] 80 bc [2] 8c b6 [2] 9b bd [2] 80 f3 [2] bd }

  condition:
    any of them
}