rule TTP_XOR_MULT_DOSStub_432d {
  strings:
    $key_432d = { 17 45 [2] 63 5d [2] 24 5f [2] 63 4e [2] 2d 42 [2] 21 48 [2] 36 43 [2] 2d 0d [2] 10 }

  condition:
    any of them
}