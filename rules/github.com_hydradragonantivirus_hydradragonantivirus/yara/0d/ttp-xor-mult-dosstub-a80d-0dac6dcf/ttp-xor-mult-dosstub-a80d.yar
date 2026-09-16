rule TTP_XOR_MULT_DOSStub_a80d {
  strings:
    $key_a80d = { fc 65 [2] 88 7d [2] cf 7f [2] 88 6e [2] c6 62 [2] ca 68 [2] dd 63 [2] c6 2d [2] fb }

  condition:
    any of them
}