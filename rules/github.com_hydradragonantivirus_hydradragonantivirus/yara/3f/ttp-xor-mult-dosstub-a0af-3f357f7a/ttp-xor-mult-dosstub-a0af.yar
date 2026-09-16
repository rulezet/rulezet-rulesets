rule TTP_XOR_MULT_DOSStub_a0af {
  strings:
    $key_a0af = { f4 c7 [2] 80 df [2] c7 dd [2] 80 cc [2] ce c0 [2] c2 ca [2] d5 c1 [2] ce 8f [2] f3 }

  condition:
    any of them
}