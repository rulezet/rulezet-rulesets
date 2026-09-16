rule TTP_XOR_MULT_DOSStub_692e {
  strings:
    $key_692e = { 3d 46 [2] 49 5e [2] 0e 5c [2] 49 4d [2] 07 41 [2] 0b 4b [2] 1c 40 [2] 07 0e [2] 3a }

  condition:
    any of them
}