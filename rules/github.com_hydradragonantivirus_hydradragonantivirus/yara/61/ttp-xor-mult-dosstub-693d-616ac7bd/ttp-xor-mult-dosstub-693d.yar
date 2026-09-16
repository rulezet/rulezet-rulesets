rule TTP_XOR_MULT_DOSStub_693d {
  strings:
    $key_693d = { 3d 55 [2] 49 4d [2] 0e 4f [2] 49 5e [2] 07 52 [2] 0b 58 [2] 1c 53 [2] 07 1d [2] 3a }

  condition:
    any of them
}