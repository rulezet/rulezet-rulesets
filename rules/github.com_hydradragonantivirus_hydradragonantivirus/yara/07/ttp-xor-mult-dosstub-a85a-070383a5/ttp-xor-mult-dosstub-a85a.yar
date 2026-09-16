rule TTP_XOR_MULT_DOSStub_a85a {
  strings:
    $key_a85a = { fc 32 [2] 88 2a [2] cf 28 [2] 88 39 [2] c6 35 [2] ca 3f [2] dd 34 [2] c6 7a [2] fb }

  condition:
    any of them
}