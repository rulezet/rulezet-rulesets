rule TTP_XOR_MULT_DOSStub_8ab8 {
  strings:
    $key_8ab8 = { de d0 [2] aa c8 [2] ed ca [2] aa db [2] e4 d7 [2] e8 dd [2] ff d6 [2] e4 98 [2] d9 }

  condition:
    any of them
}