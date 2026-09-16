rule TTP_XOR_MULT_DOSStub_28c5 {
  strings:
    $key_28c5 = { 7c ad [2] 08 b5 [2] 4f b7 [2] 08 a6 [2] 46 aa [2] 4a a0 [2] 5d ab [2] 46 e5 [2] 7b }

  condition:
    any of them
}