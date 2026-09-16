rule TTP_XOR_MULT_DOSStub_693c {
  strings:
    $key_693c = { 3d 54 [2] 49 4c [2] 0e 4e [2] 49 5f [2] 07 53 [2] 0b 59 [2] 1c 52 [2] 07 1c [2] 3a }

  condition:
    any of them
}