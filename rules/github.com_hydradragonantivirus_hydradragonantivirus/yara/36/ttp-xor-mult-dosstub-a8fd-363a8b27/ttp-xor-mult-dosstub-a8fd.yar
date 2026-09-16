rule TTP_XOR_MULT_DOSStub_a8fd {
  strings:
    $key_a8fd = { fc 95 [2] 88 8d [2] cf 8f [2] 88 9e [2] c6 92 [2] ca 98 [2] dd 93 [2] c6 dd [2] fb }

  condition:
    any of them
}