rule TTP_XOR_MULT_DOSStub_e880 {
  strings:
    $key_e880 = { bc e8 [2] c8 f0 [2] 8f f2 [2] c8 e3 [2] 86 ef [2] 8a e5 [2] 9d ee [2] 86 a0 [2] bb }

  condition:
    any of them
}