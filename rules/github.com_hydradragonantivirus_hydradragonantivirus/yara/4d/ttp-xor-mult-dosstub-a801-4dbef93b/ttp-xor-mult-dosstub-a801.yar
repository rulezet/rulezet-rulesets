rule TTP_XOR_MULT_DOSStub_a801 {
  strings:
    $key_a801 = { fc 69 [2] 88 71 [2] cf 73 [2] 88 62 [2] c6 6e [2] ca 64 [2] dd 6f [2] c6 21 [2] fb }

  condition:
    any of them
}