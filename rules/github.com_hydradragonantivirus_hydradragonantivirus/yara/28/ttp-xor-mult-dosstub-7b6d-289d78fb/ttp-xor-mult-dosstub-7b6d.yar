rule TTP_XOR_MULT_DOSStub_7b6d {
  strings:
    $key_7b6d = { 2f 05 [2] 5b 1d [2] 1c 1f [2] 5b 0e [2] 15 02 [2] 19 08 [2] 0e 03 [2] 15 4d [2] 28 }

  condition:
    any of them
}