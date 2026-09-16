rule TTP_XOR_MULT_DOSStub_2b6d {
  strings:
    $key_2b6d = { 7f 05 [2] 0b 1d [2] 4c 1f [2] 0b 0e [2] 45 02 [2] 49 08 [2] 5e 03 [2] 45 4d [2] 78 }

  condition:
    any of them
}