rule TTP_XOR_MULT_DOSStub_396d {
  strings:
    $key_396d = { 6d 05 [2] 19 1d [2] 5e 1f [2] 19 0e [2] 57 02 [2] 5b 08 [2] 4c 03 [2] 57 4d [2] 6a }

  condition:
    any of them
}