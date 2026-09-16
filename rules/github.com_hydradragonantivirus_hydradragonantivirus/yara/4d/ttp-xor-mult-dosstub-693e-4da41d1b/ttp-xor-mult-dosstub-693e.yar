rule TTP_XOR_MULT_DOSStub_693e {
  strings:
    $key_693e = { 3d 56 [2] 49 4e [2] 0e 4c [2] 49 5d [2] 07 51 [2] 0b 5b [2] 1c 50 [2] 07 1e [2] 3a }

  condition:
    any of them
}