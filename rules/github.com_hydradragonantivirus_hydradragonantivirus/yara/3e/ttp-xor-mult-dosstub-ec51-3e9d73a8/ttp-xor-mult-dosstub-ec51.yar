rule TTP_XOR_MULT_DOSStub_ec51 {
  strings:
    $key_ec51 = { b8 39 [2] cc 21 [2] 8b 23 [2] cc 32 [2] 82 3e [2] 8e 34 [2] 99 3f [2] 82 71 [2] bf }

  condition:
    any of them
}