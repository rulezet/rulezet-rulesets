rule TTP_XOR_MULT_DOSStub_b9ba {
  strings:
    $key_b9ba = { ed d2 [2] 99 ca [2] de c8 [2] 99 d9 [2] d7 d5 [2] db df [2] cc d4 [2] d7 9a [2] ea }

  condition:
    any of them
}