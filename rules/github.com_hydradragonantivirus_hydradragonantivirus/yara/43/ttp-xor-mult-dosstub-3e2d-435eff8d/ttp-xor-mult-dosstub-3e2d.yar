rule TTP_XOR_MULT_DOSStub_3e2d {
  strings:
    $key_3e2d = { 6a 45 [2] 1e 5d [2] 59 5f [2] 1e 4e [2] 50 42 [2] 5c 48 [2] 4b 43 [2] 50 0d [2] 6d }

  condition:
    any of them
}