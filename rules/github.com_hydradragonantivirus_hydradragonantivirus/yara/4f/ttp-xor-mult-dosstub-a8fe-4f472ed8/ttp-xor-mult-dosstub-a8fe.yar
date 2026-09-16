rule TTP_XOR_MULT_DOSStub_a8fe {
  strings:
    $key_a8fe = { fc 96 [2] 88 8e [2] cf 8c [2] 88 9d [2] c6 91 [2] ca 9b [2] dd 90 [2] c6 de [2] fb }

  condition:
    any of them
}