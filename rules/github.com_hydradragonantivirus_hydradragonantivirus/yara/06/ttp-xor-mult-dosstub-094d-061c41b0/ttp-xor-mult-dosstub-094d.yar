rule TTP_XOR_MULT_DOSStub_094d {
  strings:
    $key_094d = { 5d 25 [2] 29 3d [2] 6e 3f [2] 29 2e [2] 67 22 [2] 6b 28 [2] 7c 23 [2] 67 6d [2] 5a }

  condition:
    any of them
}