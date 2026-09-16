rule TTP_XOR_MULT_DOSStub_ffda {
  strings:
    $key_ffda = { ab b2 [2] df aa [2] 98 a8 [2] df b9 [2] 91 b5 [2] 9d bf [2] 8a b4 [2] 91 fa [2] ac }

  condition:
    any of them
}