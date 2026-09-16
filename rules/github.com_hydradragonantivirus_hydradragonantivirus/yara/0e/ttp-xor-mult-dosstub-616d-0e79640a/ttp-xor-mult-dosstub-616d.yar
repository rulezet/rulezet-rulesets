rule TTP_XOR_MULT_DOSStub_616d {
  strings:
    $key_616d = { 35 05 [2] 41 1d [2] 06 1f [2] 41 0e [2] 0f 02 [2] 03 08 [2] 14 03 [2] 0f 4d [2] 32 }

  condition:
    any of them
}