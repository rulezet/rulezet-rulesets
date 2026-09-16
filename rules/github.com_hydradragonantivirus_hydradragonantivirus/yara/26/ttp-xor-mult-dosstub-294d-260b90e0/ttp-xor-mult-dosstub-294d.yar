rule TTP_XOR_MULT_DOSStub_294d {
  strings:
    $key_294d = { 7d 25 [2] 09 3d [2] 4e 3f [2] 09 2e [2] 47 22 [2] 4b 28 [2] 5c 23 [2] 47 6d [2] 7a }

  condition:
    any of them
}