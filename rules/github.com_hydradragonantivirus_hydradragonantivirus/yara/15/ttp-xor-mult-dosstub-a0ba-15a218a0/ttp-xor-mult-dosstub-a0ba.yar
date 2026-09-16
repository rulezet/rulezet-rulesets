rule TTP_XOR_MULT_DOSStub_a0ba {
  strings:
    $key_a0ba = { f4 d2 [2] 80 ca [2] c7 c8 [2] 80 d9 [2] ce d5 [2] c2 df [2] d5 d4 [2] ce 9a [2] f3 }

  condition:
    any of them
}