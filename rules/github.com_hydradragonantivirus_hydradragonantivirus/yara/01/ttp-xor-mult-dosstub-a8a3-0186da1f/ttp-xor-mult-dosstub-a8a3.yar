rule TTP_XOR_MULT_DOSStub_a8a3 {
  strings:
    $key_a8a3 = { fc cb [2] 88 d3 [2] cf d1 [2] 88 c0 [2] c6 cc [2] ca c6 [2] dd cd [2] c6 83 [2] fb }

  condition:
    any of them
}