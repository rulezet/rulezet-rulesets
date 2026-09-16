rule TTP_XOR_MULT_DOSStub_072d {
  strings:
    $key_072d = { 53 45 [2] 27 5d [2] 60 5f [2] 27 4e [2] 69 42 [2] 65 48 [2] 72 43 [2] 69 0d [2] 54 }

  condition:
    any of them
}