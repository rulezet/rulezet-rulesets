rule TTP_XOR_MULT_DOSStub_b9a4 {
  strings:
    $key_b9a4 = { ed cc [2] 99 d4 [2] de d6 [2] 99 c7 [2] d7 cb [2] db c1 [2] cc ca [2] d7 84 [2] ea }

  condition:
    any of them
}