rule TTP_XOR_MULT_DOSStub_a83c {
  strings:
    $key_a83c = { fc 54 [2] 88 4c [2] cf 4e [2] 88 5f [2] c6 53 [2] ca 59 [2] dd 52 [2] c6 1c [2] fb }

  condition:
    any of them
}