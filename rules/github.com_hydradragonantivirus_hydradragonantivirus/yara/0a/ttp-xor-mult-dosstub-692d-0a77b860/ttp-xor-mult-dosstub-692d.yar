rule TTP_XOR_MULT_DOSStub_692d {
  strings:
    $key_692d = { 3d 45 [2] 49 5d [2] 0e 5f [2] 49 4e [2] 07 42 [2] 0b 48 [2] 1c 43 [2] 07 0d [2] 3a }

  condition:
    any of them
}