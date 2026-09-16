rule TTP_XOR_MULT_DOSStub_056d {
  strings:
    $key_056d = { 51 05 [2] 25 1d [2] 62 1f [2] 25 0e [2] 6b 02 [2] 67 08 [2] 70 03 [2] 6b 4d [2] 56 }

  condition:
    any of them
}