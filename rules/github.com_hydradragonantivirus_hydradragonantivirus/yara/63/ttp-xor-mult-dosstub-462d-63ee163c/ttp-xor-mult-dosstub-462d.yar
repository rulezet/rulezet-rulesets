rule TTP_XOR_MULT_DOSStub_462d {
  strings:
    $key_462d = { 12 45 [2] 66 5d [2] 21 5f [2] 66 4e [2] 28 42 [2] 24 48 [2] 33 43 [2] 28 0d [2] 15 }

  condition:
    any of them
}