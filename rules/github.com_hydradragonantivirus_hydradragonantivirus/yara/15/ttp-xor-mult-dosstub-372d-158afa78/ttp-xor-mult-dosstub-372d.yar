rule TTP_XOR_MULT_DOSStub_372d {
  strings:
    $key_372d = { 63 45 [2] 17 5d [2] 50 5f [2] 17 4e [2] 59 42 [2] 55 48 [2] 42 43 [2] 59 0d [2] 64 }

  condition:
    any of them
}