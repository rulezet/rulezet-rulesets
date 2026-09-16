rule TTP_XOR_MULT_DOSStub_57bf {
  strings:
    $key_57bf = { 03 d7 [2] 77 cf [2] 30 cd [2] 77 dc [2] 39 d0 [2] 35 da [2] 22 d1 [2] 39 9f [2] 04 }

  condition:
    any of them
}