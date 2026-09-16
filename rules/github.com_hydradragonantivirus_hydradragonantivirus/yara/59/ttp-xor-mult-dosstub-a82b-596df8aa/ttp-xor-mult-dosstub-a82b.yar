rule TTP_XOR_MULT_DOSStub_a82b {
  strings:
    $key_a82b = { fc 43 [2] 88 5b [2] cf 59 [2] 88 48 [2] c6 44 [2] ca 4e [2] dd 45 [2] c6 0b [2] fb }

  condition:
    any of them
}