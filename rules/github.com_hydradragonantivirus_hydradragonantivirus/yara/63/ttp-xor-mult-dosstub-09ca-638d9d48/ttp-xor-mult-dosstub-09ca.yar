rule TTP_XOR_MULT_DOSStub_09ca {
  strings:
    $key_09ca = { 5d a2 [2] 29 ba [2] 6e b8 [2] 29 a9 [2] 67 a5 [2] 6b af [2] 7c a4 [2] 67 ea [2] 5a }

  condition:
    any of them
}