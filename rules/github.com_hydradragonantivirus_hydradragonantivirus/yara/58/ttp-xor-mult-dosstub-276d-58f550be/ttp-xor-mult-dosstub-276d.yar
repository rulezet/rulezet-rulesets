rule TTP_XOR_MULT_DOSStub_276d {
  strings:
    $key_276d = { 73 05 [2] 07 1d [2] 40 1f [2] 07 0e [2] 49 02 [2] 45 08 [2] 52 03 [2] 49 4d [2] 74 }

  condition:
    any of them
}