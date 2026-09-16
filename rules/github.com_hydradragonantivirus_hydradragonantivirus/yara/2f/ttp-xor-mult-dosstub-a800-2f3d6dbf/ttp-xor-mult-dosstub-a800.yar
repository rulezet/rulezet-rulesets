rule TTP_XOR_MULT_DOSStub_a800 {
  strings:
    $key_a800 = { fc 68 [2] 88 70 [2] cf 72 [2] 88 63 [2] c6 6f [2] ca 65 [2] dd 6e [2] c6 20 [2] fb }

  condition:
    any of them
}