rule TTP_XOR_MULT_DOSStub_124d {
  strings:
    $key_124d = { 46 25 [2] 32 3d [2] 75 3f [2] 32 2e [2] 7c 22 [2] 70 28 [2] 67 23 [2] 7c 6d [2] 41 }

  condition:
    any of them
}