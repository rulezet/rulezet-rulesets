rule TTP_XOR_MULT_DOSStub_693f {
  strings:
    $key_693f = { 3d 57 [2] 49 4f [2] 0e 4d [2] 49 5c [2] 07 50 [2] 0b 5a [2] 1c 51 [2] 07 1f [2] 3a }

  condition:
    any of them
}