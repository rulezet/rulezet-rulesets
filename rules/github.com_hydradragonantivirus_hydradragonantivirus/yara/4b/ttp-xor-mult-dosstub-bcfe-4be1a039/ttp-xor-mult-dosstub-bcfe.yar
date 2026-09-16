rule TTP_XOR_MULT_DOSStub_bcfe {
  strings:
    $key_bcfe = { e8 96 [2] 9c 8e [2] db 8c [2] 9c 9d [2] d2 91 [2] de 9b [2] c9 90 [2] d2 de [2] ef }

  condition:
    any of them
}