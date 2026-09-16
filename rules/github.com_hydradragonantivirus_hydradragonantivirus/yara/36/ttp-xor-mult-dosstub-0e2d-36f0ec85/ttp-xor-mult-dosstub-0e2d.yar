rule TTP_XOR_MULT_DOSStub_0e2d {
  strings:
    $key_0e2d = { 5a 45 [2] 2e 5d [2] 69 5f [2] 2e 4e [2] 60 42 [2] 6c 48 [2] 7b 43 [2] 60 0d [2] 5d }

  condition:
    any of them
}