rule TTP_XOR_MULT_DOSStub_002d {
  strings:
    $key_002d = { 54 45 [2] 20 5d [2] 67 5f [2] 20 4e [2] 6e 42 [2] 62 48 [2] 75 43 [2] 6e 0d [2] 53 }

  condition:
    any of them
}