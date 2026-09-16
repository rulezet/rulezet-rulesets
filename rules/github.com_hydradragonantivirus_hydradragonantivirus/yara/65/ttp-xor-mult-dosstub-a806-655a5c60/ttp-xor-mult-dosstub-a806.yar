rule TTP_XOR_MULT_DOSStub_a806 {
  strings:
    $key_a806 = { fc 6e [2] 88 76 [2] cf 74 [2] 88 65 [2] c6 69 [2] ca 63 [2] dd 68 [2] c6 26 [2] fb }

  condition:
    any of them
}