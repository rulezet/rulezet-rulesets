rule TTP_XOR_MULT_DOSStub_693a {
  strings:
    $key_693a = { 3d 52 [2] 49 4a [2] 0e 48 [2] 49 59 [2] 07 55 [2] 0b 5f [2] 1c 54 [2] 07 1a [2] 3a }

  condition:
    any of them
}