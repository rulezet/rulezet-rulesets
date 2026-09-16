rule TTP_XOR_MULT_DOSStub_eada {
  strings:
    $key_eada = { be b2 [2] ca aa [2] 8d a8 [2] ca b9 [2] 84 b5 [2] 88 bf [2] 9f b4 [2] 84 fa [2] b9 }

  condition:
    any of them
}