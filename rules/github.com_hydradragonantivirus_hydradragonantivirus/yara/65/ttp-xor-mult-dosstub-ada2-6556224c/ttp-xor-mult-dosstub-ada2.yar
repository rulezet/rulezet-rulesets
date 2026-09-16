rule TTP_XOR_MULT_DOSStub_ada2 {
  strings:
    $key_ada2 = { f9 ca [2] 8d d2 [2] ca d0 [2] 8d c1 [2] c3 cd [2] cf c7 [2] d8 cc [2] c3 82 [2] fe }

  condition:
    any of them
}