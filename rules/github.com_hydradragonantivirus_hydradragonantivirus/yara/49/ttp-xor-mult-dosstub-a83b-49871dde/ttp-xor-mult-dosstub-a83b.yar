rule TTP_XOR_MULT_DOSStub_a83b {
  strings:
    $key_a83b = { fc 53 [2] 88 4b [2] cf 49 [2] 88 58 [2] c6 54 [2] ca 5e [2] dd 55 [2] c6 1b [2] fb }

  condition:
    any of them
}