rule TTP_XOR_MULT_DOSStub_bfc3 {
  strings:
    $key_bfc3 = { eb ab [2] 9f b3 [2] d8 b1 [2] 9f a0 [2] d1 ac [2] dd a6 [2] ca ad [2] d1 e3 [2] ec }

  condition:
    any of them
}