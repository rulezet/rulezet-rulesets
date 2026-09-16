rule TTP_XOR_MULT_DOSStub_bcf9 {
  strings:
    $key_bcf9 = { e8 91 [2] 9c 89 [2] db 8b [2] 9c 9a [2] d2 96 [2] de 9c [2] c9 97 [2] d2 d9 [2] ef }

  condition:
    any of them
}