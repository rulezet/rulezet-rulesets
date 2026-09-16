rule TTP_XOR_MULT_DOSStub_add9 {
  strings:
    $key_add9 = { f9 b1 [2] 8d a9 [2] ca ab [2] 8d ba [2] c3 b6 [2] cf bc [2] d8 b7 [2] c3 f9 [2] fe }

  condition:
    any of them
}