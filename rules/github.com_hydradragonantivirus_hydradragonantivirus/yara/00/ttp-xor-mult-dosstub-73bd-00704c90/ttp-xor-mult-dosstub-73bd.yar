rule TTP_XOR_MULT_DOSStub_73bd {
  strings:
    $key_73bd = { 27 d5 [2] 53 cd [2] 14 cf [2] 53 de [2] 1d d2 [2] 11 d8 [2] 06 d3 [2] 1d 9d [2] 20 }

  condition:
    any of them
}