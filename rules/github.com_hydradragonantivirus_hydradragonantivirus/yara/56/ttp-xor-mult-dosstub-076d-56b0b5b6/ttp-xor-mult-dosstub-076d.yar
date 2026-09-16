rule TTP_XOR_MULT_DOSStub_076d {
  strings:
    $key_076d = { 53 05 [2] 27 1d [2] 60 1f [2] 27 0e [2] 69 02 [2] 65 08 [2] 72 03 [2] 69 4d [2] 54 }

  condition:
    any of them
}