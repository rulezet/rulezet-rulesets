rule TTP_XOR_MULT_DOSStub_6a6d {
  strings:
    $key_6a6d = { 3e 05 [2] 4a 1d [2] 0d 1f [2] 4a 0e [2] 04 02 [2] 08 08 [2] 1f 03 [2] 04 4d [2] 39 }

  condition:
    any of them
}