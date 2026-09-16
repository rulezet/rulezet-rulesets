rule TTP_XOR_MULT_DOSStub_377d {
  strings:
    $key_377d = { 63 15 [2] 17 0d [2] 50 0f [2] 17 1e [2] 59 12 [2] 55 18 [2] 42 13 [2] 59 5d [2] 64 }

  condition:
    any of them
}