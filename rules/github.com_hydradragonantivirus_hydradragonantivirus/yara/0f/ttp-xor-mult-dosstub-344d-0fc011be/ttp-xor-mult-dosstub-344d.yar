rule TTP_XOR_MULT_DOSStub_344d {
  strings:
    $key_344d = { 60 25 [2] 14 3d [2] 53 3f [2] 14 2e [2] 5a 22 [2] 56 28 [2] 41 23 [2] 5a 6d [2] 67 }

  condition:
    any of them
}