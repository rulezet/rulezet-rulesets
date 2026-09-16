rule TTP_XOR_MULT_DOSStub_2e2d {
  strings:
    $key_2e2d = { 7a 45 [2] 0e 5d [2] 49 5f [2] 0e 4e [2] 40 42 [2] 4c 48 [2] 5b 43 [2] 40 0d [2] 7d }

  condition:
    any of them
}