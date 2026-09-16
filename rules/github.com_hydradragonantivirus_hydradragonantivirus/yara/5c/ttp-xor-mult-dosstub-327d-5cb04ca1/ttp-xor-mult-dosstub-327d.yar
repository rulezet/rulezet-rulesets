rule TTP_XOR_MULT_DOSStub_327d {
  strings:
    $key_327d = { 66 15 [2] 12 0d [2] 55 0f [2] 12 1e [2] 5c 12 [2] 50 18 [2] 47 13 [2] 5c 5d [2] 61 }

  condition:
    any of them
}