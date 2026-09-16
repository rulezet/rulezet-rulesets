rule TTP_XOR_MULT_DOSStub_ec81 {
  strings:
    $key_ec81 = { b8 e9 [2] cc f1 [2] 8b f3 [2] cc e2 [2] 82 ee [2] 8e e4 [2] 99 ef [2] 82 a1 [2] bf }

  condition:
    any of them
}