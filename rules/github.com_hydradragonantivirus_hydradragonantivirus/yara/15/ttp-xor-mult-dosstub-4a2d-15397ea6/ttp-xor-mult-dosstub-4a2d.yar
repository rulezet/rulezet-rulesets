rule TTP_XOR_MULT_DOSStub_4a2d {
  strings:
    $key_4a2d = { 1e 45 [2] 6a 5d [2] 2d 5f [2] 6a 4e [2] 24 42 [2] 28 48 [2] 3f 43 [2] 24 0d [2] 19 }

  condition:
    any of them
}