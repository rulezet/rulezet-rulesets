rule TTP_XOR_MULT_DOSStub_562d {
  strings:
    $key_562d = { 02 45 [2] 76 5d [2] 31 5f [2] 76 4e [2] 38 42 [2] 34 48 [2] 23 43 [2] 38 0d [2] 05 }

  condition:
    any of them
}