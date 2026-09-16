rule TTP_XOR_MULT_DOSStub_a897 {
  strings:
    $key_a897 = { fc ff [2] 88 e7 [2] cf e5 [2] 88 f4 [2] c6 f8 [2] ca f2 [2] dd f9 [2] c6 b7 [2] fb }

  condition:
    any of them
}