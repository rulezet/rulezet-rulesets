rule TTP_XOR_MULT_DOSStub_a85b {
  strings:
    $key_a85b = { fc 33 [2] 88 2b [2] cf 29 [2] 88 38 [2] c6 34 [2] ca 3e [2] dd 35 [2] c6 7b [2] fb }

  condition:
    any of them
}