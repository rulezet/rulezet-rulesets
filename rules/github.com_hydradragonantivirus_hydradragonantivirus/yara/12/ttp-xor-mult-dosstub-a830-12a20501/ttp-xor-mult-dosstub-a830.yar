rule TTP_XOR_MULT_DOSStub_a830 {
  strings:
    $key_a830 = { fc 58 [2] 88 40 [2] cf 42 [2] 88 53 [2] c6 5f [2] ca 55 [2] dd 5e [2] c6 10 [2] fb }

  condition:
    any of them
}