rule TTP_XOR_MULT_DOSStub_07bf {
  strings:
    $key_07bf = { 53 d7 [2] 27 cf [2] 60 cd [2] 27 dc [2] 69 d0 [2] 65 da [2] 72 d1 [2] 69 9f [2] 54 }

  condition:
    any of them
}