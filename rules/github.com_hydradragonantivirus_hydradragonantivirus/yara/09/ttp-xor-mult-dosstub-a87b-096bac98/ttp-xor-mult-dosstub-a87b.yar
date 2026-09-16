rule TTP_XOR_MULT_DOSStub_a87b {
  strings:
    $key_a87b = { fc 13 [2] 88 0b [2] cf 09 [2] 88 18 [2] c6 14 [2] ca 1e [2] dd 15 [2] c6 5b [2] fb }

  condition:
    any of them
}