rule TTP_XOR_MULT_DOSStub_258b {
  strings:
    $key_258b = { 71 e3 [2] 05 fb [2] 42 f9 [2] 05 e8 [2] 4b e4 [2] 47 ee [2] 50 e5 [2] 4b ab [2] 76 }

  condition:
    any of them
}