rule TTP_XOR_MULT_DOSStub_8b8a {
  strings:
    $key_8b8a = { df e2 [2] ab fa [2] ec f8 [2] ab e9 [2] e5 e5 [2] e9 ef [2] fe e4 [2] e5 aa [2] d8 }

  condition:
    any of them
}