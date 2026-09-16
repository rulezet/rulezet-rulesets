rule TTP_XOR_MULT_DOSStub_3d6d {
  strings:
    $key_3d6d = { 69 05 [2] 1d 1d [2] 5a 1f [2] 1d 0e [2] 53 02 [2] 5f 08 [2] 48 03 [2] 53 4d [2] 6e }

  condition:
    any of them
}