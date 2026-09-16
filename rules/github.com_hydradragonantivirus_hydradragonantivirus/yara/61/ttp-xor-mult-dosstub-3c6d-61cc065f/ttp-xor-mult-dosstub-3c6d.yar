rule TTP_XOR_MULT_DOSStub_3c6d {
  strings:
    $key_3c6d = { 68 05 [2] 1c 1d [2] 5b 1f [2] 1c 0e [2] 52 02 [2] 5e 08 [2] 49 03 [2] 52 4d [2] 6f }

  condition:
    any of them
}