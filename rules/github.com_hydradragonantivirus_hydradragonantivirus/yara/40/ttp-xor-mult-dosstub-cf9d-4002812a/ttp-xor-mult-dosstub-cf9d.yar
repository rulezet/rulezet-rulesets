rule TTP_XOR_MULT_DOSStub_cf9d {
  strings:
    $key_cf9d = { 9b f5 [2] ef ed [2] a8 ef [2] ef fe [2] a1 f2 [2] ad f8 [2] ba f3 [2] a1 bd [2] 9c }

  condition:
    any of them
}