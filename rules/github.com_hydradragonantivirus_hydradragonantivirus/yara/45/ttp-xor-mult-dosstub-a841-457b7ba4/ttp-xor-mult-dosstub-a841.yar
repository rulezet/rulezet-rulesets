rule TTP_XOR_MULT_DOSStub_a841 {
  strings:
    $key_a841 = { fc 29 [2] 88 31 [2] cf 33 [2] 88 22 [2] c6 2e [2] ca 24 [2] dd 2f [2] c6 61 [2] fb }

  condition:
    any of them
}