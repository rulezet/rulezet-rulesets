rule TTP_XOR_MULT_DOSStub_a8fb {
  strings:
    $key_a8fb = { fc 93 [2] 88 8b [2] cf 89 [2] 88 98 [2] c6 94 [2] ca 9e [2] dd 95 [2] c6 db [2] fb }

  condition:
    any of them
}