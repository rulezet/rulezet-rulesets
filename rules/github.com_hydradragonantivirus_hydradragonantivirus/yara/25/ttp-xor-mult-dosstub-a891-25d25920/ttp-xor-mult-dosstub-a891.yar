rule TTP_XOR_MULT_DOSStub_a891 {
  strings:
    $key_a891 = { fc f9 [2] 88 e1 [2] cf e3 [2] 88 f2 [2] c6 fe [2] ca f4 [2] dd ff [2] c6 b1 [2] fb }

  condition:
    any of them
}