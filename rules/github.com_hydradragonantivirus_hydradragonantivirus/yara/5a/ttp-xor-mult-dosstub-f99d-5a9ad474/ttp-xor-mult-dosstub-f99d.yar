rule TTP_XOR_MULT_DOSStub_f99d {
  strings:
    $key_f99d = { ad f5 [2] d9 ed [2] 9e ef [2] d9 fe [2] 97 f2 [2] 9b f8 [2] 8c f3 [2] 97 bd [2] aa }

  condition:
    any of them
}