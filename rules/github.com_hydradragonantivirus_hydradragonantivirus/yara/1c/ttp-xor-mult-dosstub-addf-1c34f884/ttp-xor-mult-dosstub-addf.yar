rule TTP_XOR_MULT_DOSStub_addf {
  strings:
    $key_addf = { f9 b7 [2] 8d af [2] ca ad [2] 8d bc [2] c3 b0 [2] cf ba [2] d8 b1 [2] c3 ff [2] fe }

  condition:
    any of them
}