rule TTP_XOR_MULT_DOSStub_ee97 {
  strings:
    $key_ee97 = { ba ff [2] ce e7 [2] 89 e5 [2] ce f4 [2] 80 f8 [2] 8c f2 [2] 9b f9 [2] 80 b7 [2] bd }

  condition:
    any of them
}