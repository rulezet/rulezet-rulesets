rule TTP_XOR_MULT_DOSStub_a876 {
  strings:
    $key_a876 = { fc 1e [2] 88 06 [2] cf 04 [2] 88 15 [2] c6 19 [2] ca 13 [2] dd 18 [2] c6 56 [2] fb }

  condition:
    any of them
}