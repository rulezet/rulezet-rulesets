rule TTP_XOR_MULT_DOSStub_6b6d {
  strings:
    $key_6b6d = { 3f 05 [2] 4b 1d [2] 0c 1f [2] 4b 0e [2] 05 02 [2] 09 08 [2] 1e 03 [2] 05 4d [2] 38 }

  condition:
    any of them
}