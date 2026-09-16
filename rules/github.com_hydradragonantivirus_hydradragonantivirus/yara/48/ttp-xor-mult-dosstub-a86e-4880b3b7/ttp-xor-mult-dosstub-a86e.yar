rule TTP_XOR_MULT_DOSStub_a86e {
  strings:
    $key_a86e = { fc 06 [2] 88 1e [2] cf 1c [2] 88 0d [2] c6 01 [2] ca 0b [2] dd 00 [2] c6 4e [2] fb }

  condition:
    any of them
}