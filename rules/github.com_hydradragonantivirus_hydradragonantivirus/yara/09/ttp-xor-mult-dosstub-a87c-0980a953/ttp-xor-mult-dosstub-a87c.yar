rule TTP_XOR_MULT_DOSStub_a87c {
  strings:
    $key_a87c = { fc 14 [2] 88 0c [2] cf 0e [2] 88 1f [2] c6 13 [2] ca 19 [2] dd 12 [2] c6 5c [2] fb }

  condition:
    any of them
}