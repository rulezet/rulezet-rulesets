rule TTP_XOR_MULT_DOSStub_386d {
  strings:
    $key_386d = { 6c 05 [2] 18 1d [2] 5f 1f [2] 18 0e [2] 56 02 [2] 5a 08 [2] 4d 03 [2] 56 4d [2] 6b }

  condition:
    any of them
}