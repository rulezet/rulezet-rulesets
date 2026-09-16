rule TTP_XOR_MULT_DOSStub_a87a {
  strings:
    $key_a87a = { fc 12 [2] 88 0a [2] cf 08 [2] 88 19 [2] c6 15 [2] ca 1f [2] dd 14 [2] c6 5a [2] fb }

  condition:
    any of them
}