rule TTP_XOR_MULT_DOSStub_eec4 {
  strings:
    $key_eec4 = { ba ac [2] ce b4 [2] 89 b6 [2] ce a7 [2] 80 ab [2] 8c a1 [2] 9b aa [2] 80 e4 [2] bd }

  condition:
    any of them
}