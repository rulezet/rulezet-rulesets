rule TTP_XOR_MULT_DOSStub_2b9a {
  strings:
    $key_2b9a = { 7f f2 [2] 0b ea [2] 4c e8 [2] 0b f9 [2] 45 f5 [2] 49 ff [2] 5e f4 [2] 45 ba [2] 78 }

  condition:
    any of them
}