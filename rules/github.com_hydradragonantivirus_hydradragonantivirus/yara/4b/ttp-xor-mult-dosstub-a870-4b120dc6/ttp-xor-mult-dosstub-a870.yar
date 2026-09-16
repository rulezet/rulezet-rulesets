rule TTP_XOR_MULT_DOSStub_a870 {
  strings:
    $key_a870 = { fc 18 [2] 88 00 [2] cf 02 [2] 88 13 [2] c6 1f [2] ca 15 [2] dd 1e [2] c6 50 [2] fb }

  condition:
    any of them
}