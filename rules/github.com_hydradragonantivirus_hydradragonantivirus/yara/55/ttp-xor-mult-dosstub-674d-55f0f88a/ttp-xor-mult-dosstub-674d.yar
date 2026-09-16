rule TTP_XOR_MULT_DOSStub_674d {
  strings:
    $key_674d = { 33 25 [2] 47 3d [2] 00 3f [2] 47 2e [2] 09 22 [2] 05 28 [2] 12 23 [2] 09 6d [2] 34 }

  condition:
    any of them
}