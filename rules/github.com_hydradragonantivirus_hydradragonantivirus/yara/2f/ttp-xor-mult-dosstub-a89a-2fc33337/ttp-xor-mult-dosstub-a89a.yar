rule TTP_XOR_MULT_DOSStub_a89a {
  strings:
    $key_a89a = { fc f2 [2] 88 ea [2] cf e8 [2] 88 f9 [2] c6 f5 [2] ca ff [2] dd f4 [2] c6 ba [2] fb }

  condition:
    any of them
}