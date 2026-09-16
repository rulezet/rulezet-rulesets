rule TTP_XOR_MULT_DOSStub_e886 {
  strings:
    $key_e886 = { bc ee [2] c8 f6 [2] 8f f4 [2] c8 e5 [2] 86 e9 [2] 8a e3 [2] 9d e8 [2] 86 a6 [2] bb }

  condition:
    any of them
}