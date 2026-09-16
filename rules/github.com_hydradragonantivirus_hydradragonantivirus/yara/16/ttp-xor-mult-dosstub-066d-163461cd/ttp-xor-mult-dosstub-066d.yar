rule TTP_XOR_MULT_DOSStub_066d {
  strings:
    $key_066d = { 52 05 [2] 26 1d [2] 61 1f [2] 26 0e [2] 68 02 [2] 64 08 [2] 73 03 [2] 68 4d [2] 55 }

  condition:
    any of them
}