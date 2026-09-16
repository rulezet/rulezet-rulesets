rule TTP_XOR_MULT_DOSStub_d2ba {
  strings:
    $key_d2ba = { 86 d2 [2] f2 ca [2] b5 c8 [2] f2 d9 [2] bc d5 [2] b0 df [2] a7 d4 [2] bc 9a [2] 81 }

  condition:
    any of them
}