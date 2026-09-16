rule TTP_XOR_MULT_DOSStub_a811 {
  strings:
    $key_a811 = { fc 79 [2] 88 61 [2] cf 63 [2] 88 72 [2] c6 7e [2] ca 74 [2] dd 7f [2] c6 31 [2] fb }

  condition:
    any of them
}